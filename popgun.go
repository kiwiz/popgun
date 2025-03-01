/*
- implementation of POP3 server according to rfc1939, rfc2449 in progress
*/

package popgun

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

const (
	STATE_AUTHORIZATION = iota + 1
	STATE_TRANSACTION
	STATE_UPDATE
)

// Logger is the behaviour used by server/client to
// report errors for accepting connections and unexpected behavior from handlers.
type Logger interface {
	Printf(format string, v ...interface{})
	Println(v ...interface{})
}

type Authorizator interface {
	Authorize(conn net.Conn, user, pass string) error
}

type Backend interface {
	Stat(user string) (messages, octets int, err error)
	List(user string) (octets []int, err error)
	ListMessage(user string, msgId int) (exists bool, octets int, err error)
	Retr(user string, msgId int) (message string, err error)
	Dele(user string, msgId int) error
	Rset(user string) error
	Uidl(user string) (uids []string, err error)
	UidlMessage(user string, msgId int) (exists bool, uid string, err error)
	Top(user string, msgId int, n int) (lines []string, err error)
	Update(user string) error
	Lock(user string) error
	Unlock(user string) error
}

var (
	ErrInvalidState = fmt.Errorf("Invalid state")
)

//---------------CLIENT

type Client struct {
	conn              net.Conn
	commands          map[string]Executable
	printer           *Printer
	isAlive           bool
	currentState      int
	authorizator      Authorizator
	backend           Backend
	user              string
	pass              string
	lastCommand       string
	allowInsecureAuth bool

	ErrorLog Logger
	DebugLog Logger
}

func newClient(conn net.Conn, authorizator Authorizator, backend Backend, allowInsecureAuth bool) *Client {
	commands := make(map[string]Executable)

	commands["QUIT"] = QuitCommand{}
	commands["USER"] = UserCommand{}
	commands["PASS"] = PassCommand{}
	commands["STAT"] = StatCommand{}
	commands["LIST"] = ListCommand{}
	commands["RETR"] = RetrCommand{}
	commands["DELE"] = DeleCommand{}
	commands["NOOP"] = NoopCommand{}
	commands["RSET"] = RsetCommand{}
	commands["UIDL"] = UidlCommand{}
	commands["CAPA"] = CapaCommand{}
	commands["TOP"] = TopCommand{}

	return &Client{
		conn:              conn,
		commands:          commands,
		currentState:      STATE_AUTHORIZATION,
		authorizator:      authorizator,
		backend:           backend,
		allowInsecureAuth: allowInsecureAuth,
	}
}

func (c Client) AllowAuth() bool {
	tlsConn, _ := c.conn.(*tls.Conn)
	return c.allowInsecureAuth || tlsConn != nil
}

func (c Client) handle() {
	defer c.conn.Close()
	c.conn.SetReadDeadline(time.Now().Add(1 * time.Minute))
	c.printer = NewPrinter(c.conn)

	c.isAlive = true
	reader := bufio.NewReader(c.conn)

	c.printer.Welcome()

	for c.isAlive {
		// according to RFC commands are terminated by CRLF, but we are removing \r in parseInput
		input, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				c.DebugLog.Println("Connection closed by client")
			} else {
				c.DebugLog.Println("Error reading input: ", err)
			}
			if len(c.user) > 0 {
				c.DebugLog.Println("Unlocking user %s due to connection error ", c.user)
				c.backend.Unlock(c.user)
			}
			break
		}

		cmd, args := c.parseInput(input)
		exec, ok := c.commands[cmd]
		if !ok {
			c.printer.Err("Invalid command %s", cmd)
			c.DebugLog.Printf("Invalid command: %s", cmd)
			continue
		}
		state, err := exec.Run(&c, args)
		if err != nil {
			c.printer.Err("Error executing command %s", cmd)
			c.DebugLog.Println("Error executing command: ", err)
			continue
		}
		c.lastCommand = cmd
		c.currentState = state
	}
}

func (c Client) parseInput(input string) (string, []string) {
	input = strings.Trim(input, "\r \n")
	cmd := strings.Split(input, " ")
	return strings.ToUpper(cmd[0]), cmd[1:]
}

//---------------SERVER

type Server struct {
	auth    Authorizator
	backend Backend

	AllowInsecureAuth bool
	DebugLog          Logger
	ErrorLog          Logger
}

func NewServer(auth Authorizator, backend Backend) *Server {
	return &Server{
		auth:    auth,
		backend: backend,

		AllowInsecureAuth: false,
		DebugLog:          log.New(os.Stderr, "pop3/debug: ", 0),
		ErrorLog:          log.New(os.Stderr, "pop3/error: ", 0),
	}
}

func (s Server) Serve(l net.Listener) error {
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				s.ErrorLog.Println("Error: could not accept connection: ", err)
				continue
			}

			c := newClient(conn, s.auth, s.backend, s.AllowInsecureAuth)
			c.ErrorLog = s.ErrorLog
			c.DebugLog = s.DebugLog
			go c.handle()
		}
	}()

	return nil
}

//---------------PRINTER

type Printer struct {
	conn net.Conn
}

func NewPrinter(conn net.Conn) *Printer {
	return &Printer{conn}
}

func (p Printer) Welcome() {
	fmt.Fprintf(p.conn, "+OK POPgun POP3 server ready\r\n")
}

func (p Printer) Ok(msg string, a ...interface{}) {
	fmt.Fprintf(p.conn, "+OK %s\r\n", fmt.Sprintf(msg, a...))
}

func (p Printer) Err(msg string, a ...interface{}) {
	fmt.Fprintf(p.conn, "-ERR %s\r\n", fmt.Sprintf(msg, a...))
}

func (p Printer) MultiLine(msgs []string) {
	for _, line := range msgs {
		line := strings.Trim(line, "\r")
		if strings.HasPrefix(line, ".") {
			fmt.Fprintf(p.conn, ".%s\r\n", line)
		} else {
			fmt.Fprintf(p.conn, "%s\r\n", line)
		}
	}
	fmt.Fprint(p.conn, ".\r\n")
}
