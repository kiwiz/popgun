package popgun

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/kiwiz/popgun/backends"
)

func TestClient_handle(t *testing.T) {
	s, c := net.Pipe()
	defer s.Close()
	defer c.Close()

	backend := backends.DummyBackend{}
	authorizator := backends.DummyAuthorizator{}
	insecure := true
	client := newClient(s, authorizator, backend, insecure)
	client.ErrorLog = log.Default()
	client.DebugLog = log.Default()

	go func() {
		client.handle()
	}()

	reader := bufio.NewReader(c)
	//read welcome message
	response, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}

	//invalid command
	expected := "-ERR Invalid command INVALID\r\n"
	fmt.Fprintf(c, "INVALID\n")
	response, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if response != expected {
		t.Errorf("Expected '%s', but got '%s'", expected, response)
	}
	//error executing command - rset cannot be executed in current state
	expected = "-ERR Error executing command RSET\r\n"
	fmt.Fprintf(c, "RSET\n")
	response, err = reader.ReadString('\n')
	if response != expected {
		t.Errorf("Expected '%s', but got '%s'", expected, response)
	}
	//successful command
	expected = "+OK Goodbye\r\n"
	fmt.Fprintf(c, "QUIT\n")
	response, err = reader.ReadString('\n')
	if response != expected {
		t.Errorf("Expected '%s', but got '%s'", expected, response)
	}
}

func TestClient_parseInput(t *testing.T) {
	conn := &net.IPConn{}
	backend := backends.DummyBackend{}
	authorizator := backends.DummyAuthorizator{}
	insecure := true
	client := newClient(conn, authorizator, backend, insecure)

	tables := [][][]string{
		{{"COMMAND1"}, {"COMMAND1"}},
		{{"COMMAND1   "}, {"COMMAND1"}},
		{{"COMMAND1 \r \n "}, {"COMMAND1"}},
		{{"comm ARG"}, {"COMM", "ARG"}},
		{{"COMM arg"}, {"COMM", "arg"}},
		{{"COMM ARG1 ARG2"}, {"COMM", "ARG1", "ARG2"}},
	}
	for _, testCase := range tables {
		inputCmd := testCase[0][0]
		cmd, args := client.parseInput(inputCmd)
		expectedCmd := testCase[1][0]
		if cmd != expectedCmd {
			t.Errorf("Expected '%s', but got '%s'", expectedCmd, cmd)
		}
		expectedArgs := testCase[1][1:]
		if !reflect.DeepEqual(args, expectedArgs) {
			t.Errorf("Expected '%s', but got '%s'", expectedArgs, args)
		}
	}
}

func TestServer_Start(t *testing.T) {
	iface := "localhost:3001"
	listener, err := net.Listen("tcp", iface)
	if err != nil {
		t.Fatal(err)
	}

	backend := backends.DummyBackend{}
	authorizator := backends.DummyAuthorizator{}
	server := NewServer(authorizator, backend)
	server.Serve(listener)

	conn, err := net.DialTimeout("tcp", iface, 3*time.Second)
	if err != nil {
		t.Errorf("Expected listening on '%s', but could not connect", iface)
		return
	}
	defer conn.Close()
}

type printerFunc func(conn net.Conn)

func printerTest(t *testing.T, f printerFunc) string {
	s, c := net.Pipe()
	defer s.Close()

	go func() {
		f(c)
		c.Close()
	}()

	buf, err := ioutil.ReadAll(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(buf[:])
}

func TestPrinter_Welcome(t *testing.T) {
	expected := "+OK POPgun POP3 server ready\r\n"

	msg := printerTest(t, func(conn net.Conn) {
		p := NewPrinter(conn)
		p.Welcome()
	})

	if msg != expected {
		t.Errorf("Expected '%s', but got '%s'", expected, msg)
	}
}

func TestPrinter_Ok(t *testing.T) {
	expected := "+OK 2 foxes jumping over lazy dog\r\n"

	msg := printerTest(t, func(conn net.Conn) {
		p := NewPrinter(conn)
		p.Ok("%d foxes jumping over lazy dog", 2)
	})

	if msg != expected {
		t.Errorf("Expected '%s', but got '%s'", expected, msg)
	}
}

func TestPrinter_Err(t *testing.T) {
	expected := "-ERR everything wrong in 10 seconds\r\n"

	msg := printerTest(t, func(conn net.Conn) {
		p := NewPrinter(conn)
		p.Err("everything wrong in %d seconds", 10)
	})

	if msg != expected {
		t.Errorf("Expected '%s', but got '%s'", expected, msg)
	}
}

func TestPrinter_MultiLine(t *testing.T) {
	expected := "multi\r\nline\r\n.\r\n"

	msg := printerTest(t, func(conn net.Conn) {
		p := NewPrinter(conn)
		p.MultiLine([]string{"multi", "line"})
	})

	if msg != expected {
		t.Errorf("Expected '%s', but got '%s'", expected, msg)
	}
}
