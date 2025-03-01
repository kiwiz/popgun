package popgun

import (
	"fmt"
	"strconv"
	"strings"
)

// https://datatracker.ietf.org/doc/html/rfc1939

type Executable interface {
	Run(c *Client, args []string) (int, error)
}

/* QUIT command

In AUTHORIZATION state

QUIT

	Arguments: none

	Restrictions: none

	Possible Responses:
		+OK

	Examples:
		C: QUIT
		S: +OK dewey POP3 server signing off

In TRANSACTION state

QUIT

	Arguments: none

	Restrictions: none

	Discussion:
		The POP3 server removes all messages marked as deleted
		from the maildrop and replies as to the status of this
		operation.  If there is an error, such as a resource
		shortage, encountered while removing messages, the
		maildrop may result in having some or none of the messages
		marked as deleted be removed.  In no case may the server
		remove any messages not marked as deleted.

		Whether the removal was successful or not, the server
		then releases any exclusive-access lock on the maildrop
		and closes the TCP connection.

	Possible Responses:
		+OK
		-ERR some deleted messages not removed

	Examples:
		C: QUIT
		S: +OK dewey POP3 server signing off (maildrop empty)
		...
		C: QUIT

*/

type QuitCommand struct{}

func (cmd QuitCommand) Run(c *Client, args []string) (int, error) {
	newState := c.currentState
	c.isAlive = false
	if c.currentState == STATE_TRANSACTION {
		// According to the RFC, we should enter UPDATE state regardless of the success of the operation.
		newState = STATE_UPDATE
		err := c.backend.Update(c.user)
		if err != nil {
			return 0, fmt.Errorf("Error updating maildrop for user %s: %v", c.user.Username(), err)
		}
		err = c.backend.Unlock(c.user)
		c.user = nil
		if err != nil {
			c.printer.Err("Server was unable to unlock maildrop")
			return 0, fmt.Errorf("Error unlocking maildrop for user %s: %v", c.user.Username(), err)
		}
	}

	c.printer.Ok("Goodbye")

	return newState, nil
}

/*
USER name

	Arguments:
		a string identifying a mailbox (required), which is of
		significance ONLY to the server

	Restrictions:
		may only be given in the AUTHORIZATION state after the POP3
		greeting or after an unsuccessful USER or PASS command

	Discussion:
		To authenticate using the USER and PASS command
		combination, the client must first issue the USER
		command.  If the POP3 server responds with a positive
		status indicator ("+OK"), then the client may issue
		either the PASS command to complete the authentication,
		or the QUIT command to terminate the POP3 session.  If
		the POP3 server responds with a negative status indicator
		("-ERR") to the USER command, then the client may either
		issue a new authentication command or may issue the QUIT
		command.

		The server may return a positive response even though no
		such mailbox exists.  The server may return a negative
		response if mailbox exists, but does not permit plaintext
		password authentication.

	Possible Responses:
		+OK name is a valid mailbox
		-ERR never heard of mailbox name

	Examples:
		C: USER frated
		S: -ERR sorry, no mailbox for frated here
		...
		C: USER mrose
		S: +OK mrose is a real hoopy frood
*/

type UserCommand struct{}

func (cmd UserCommand) Run(c *Client, args []string) (int, error) {
	if c.currentState != STATE_AUTHORIZATION {
		return 0, ErrInvalidState
	}
	if !c.AllowAuth() {
		return 0, fmt.Errorf("Authentication disabled")
	}
	if len(args) != 1 {
		return 0, fmt.Errorf("Invalid arguments count: %d", len(args))
	}
	c.username = args[0]
	c.printer.Ok("")
	return STATE_AUTHORIZATION, nil
}

/*
PASS string

Arguments:
	a server/mailbox-specific password (required)

Restrictions:
	may only be given in the AUTHORIZATION state immediately
	after a successful USER command

Discussion:
	When the client issues the PASS command, the POP3 server
	uses the argument pair from the USER and PASS commands to
	determine if the client should be given access to the
	appropriate maildrop.

	Since the PASS command has exactly one argument, a POP3
	server may treat spaces in the argument as part of the
	password, instead of as argument separators.

Possible Responses:
	+OK maildrop locked and ready
	-ERR invalid password
	-ERR unable to lock maildrop

Examples:
	C: USER mrose
	S: +OK mrose is a real hoopy frood
	C: PASS secret
	S: -ERR maildrop already locked
	  ...
	C: USER mrose
	S: +OK mrose is a real hoopy frood
	C: PASS secret
	S: +OK mrose's maildrop has 2 messages (320 octets)
*/

type PassCommand struct{}

func (cmd PassCommand) Run(c *Client, args []string) (int, error) {
	if c.currentState != STATE_AUTHORIZATION {
		return 0, ErrInvalidState
	}
	if !c.AllowAuth() {
		return 0, fmt.Errorf("Authentication disabled")
	}
	if c.lastCommand != "USER" {
		c.printer.Err("PASS can be executed only directly after USER command")
		return STATE_AUTHORIZATION, nil
	}
	if len(args) != 1 {
		return 0, fmt.Errorf("Invalid arguments count: %d", len(args))
	}
	password := args[0]
	user, err := c.authorizator.Authorize(c.conn, c.username, password)
	c.user = user
	c.username = ""
	if err != nil {
		c.printer.Err("Invalid username or password: %v", err)
		return STATE_AUTHORIZATION, nil
	}

	err = c.backend.Lock(user)
	if err != nil {
		c.printer.Err("Server was unable to lock maildrop")
		return 0, fmt.Errorf("Error locking maildrop for user %s: %v", c.user.Username(), err)
	}

	c.printer.Ok("User Successfully Logged on")

	return STATE_TRANSACTION, nil
}

/*
STAT

	Arguments: none

	Restrictions:
		may only be given in the TRANSACTION state

	Discussion:
		The POP3 server issues a positive response with a line
		containing information for the maildrop.  This line is
		called a "drop listing" for that maildrop.

		In order to simplify parsing, all POP3 servers are
		required to use a certain format for drop listings.  The
		positive response consists of "+OK" followed by a single
		space, the number of messages in the maildrop, a single
		space, and the size of the maildrop in octets.  This memo
		makes no requirement on what follows the maildrop size.
		Minimal implementations should just end that line of the
		response with a CRLF pair.  More advanced implementations
		may include other information.

		NOTE: This memo STRONGLY discourages implementations
		from supplying additional information in the drop
		listing.  Other, optional, facilities are discussed
		later on which permit the client to parse the messages
		in the maildrop.

		Note that messages marked as deleted are not counted in
		either total.

	Possible Responses:
		+OK nn mm

	Examples:
		C: STAT
		S: +OK 2 320
*/

type StatCommand struct{}

func (cmd StatCommand) Run(c *Client, args []string) (int, error) {
	if c.currentState != STATE_TRANSACTION {
		return 0, ErrInvalidState
	}

	messages, octets, err := c.backend.Stat(c.user)
	if err != nil {
		return 0, fmt.Errorf("Error calling Stat for user %s: %v", c.user.Username(), err)
	}
	c.printer.Ok("%d %d", messages, octets)
	return STATE_TRANSACTION, nil
}

/*
LIST [msg]

	Arguments:
		a message-number (optional), which, if present, may NOT
		refer to a message marked as deleted
	Restrictions:
		may only be given in the TRANSACTION state

	Discussion:
		If an argument was given and the POP3 server issues a
		positive response with a line containing information for
		that message.  This line is called a "scan listing" for
		that message.

		If no argument was given and the POP3 server issues a
		positive response, then the response given is multi-line.
		After the initial +OK, for each message in the maildrop,
		the POP3 server responds with a line containing
		information for that message.  This line is also called a
		"scan listing" for that message.  If there are no
		messages in the maildrop, then the POP3 server responds
		with no scan listings--it issues a positive response
		followed by a line containing a termination octet and a
		CRLF pair.

		In order to simplify parsing, all POP3 servers are
		required to use a certain format for scan listings.  A
		scan listing consists of the message-number of the
		message, followed by a single space and the exact size of
		the message in octets.  Methods for calculating the exact
		size of the message are described in the "Message Format"
		section below.  This memo makes no requirement on what
		follows the message size in the scan listing.  Minimal
		implementations should just end that line of the response
		with a CRLF pair.  More advanced implementations may
		include other information, as parsed from the message.

		NOTE: This memo STRONGLY discourages implementations
		from supplying additional information in the scan
		listing.  Other, optional, facilities are discussed
		later on which permit the client to parse the messages
		in the maildrop.

		Note that messages marked as deleted are not listed.

	Possible Responses:
		+OK scan listing follows
		-ERR no such message

	Examples:
		C: LIST
		S: +OK 2 messages (320 octets)
		S: 1 120

		S: 2 200
		S: .
		...
		C: LIST 2
		S: +OK 2 200
		...
		C: LIST 3
		S: -ERR no such message, only 2 messages in maildrop

*/

type ListCommand struct{}

func (cmd ListCommand) Run(c *Client, args []string) (int, error) {
	if c.currentState != STATE_TRANSACTION {
		return 0, ErrInvalidState
	}

	if len(args) > 0 {
		msgId, err := strconv.Atoi(args[0])
		if err != nil {
			c.printer.Err("Invalid argument: %s", args[0])
			return 0, fmt.Errorf("Invalid argument for LIST given by user %s: %v", c.user.Username(), err)
		}
		exists, octets, err := c.backend.ListMessage(c.user, msgId)
		if err != nil {
			return 0, fmt.Errorf("Error calling 'LIST %d' for user %s: %v", msgId, c.user.Username(), err)
		}
		if !exists {
			c.printer.Err("no such message")
			return STATE_TRANSACTION, nil
		}
		c.printer.Ok("%d %d", msgId, octets)
	} else {
		octets, err := c.backend.List(c.user)
		if err != nil {
			return 0, fmt.Errorf("Error calling LIST for user %s: %v", c.user.Username(), err)
		}
		c.printer.Ok("%d messages", len(octets))
		messagesList := make([]string, len(octets))
		for i, octet := range octets {
			messagesList[i] = fmt.Sprintf("%d %d", i+1, octet)
		}
		c.printer.MultiLine(messagesList)
	}

	return STATE_TRANSACTION, nil
}

/*

RETR msg

	Arguments:
		a message-number (required) which may NOT refer to a
		message marked as deleted

	Restrictions:
		may only be given in the TRANSACTION state

	Discussion:
		If the POP3 server issues a positive response, then the
		response given is multi-line.  After the initial +OK, the
		POP3 server sends the message corresponding to the given
		message-number, being careful to byte-stuff the termination
		character (as with all multi-line responses).

	Possible Responses:
		+OK message follows
		-ERR no such message

	Examples:
		C: RETR 1
		S: +OK 120 octets
		S: <the POP3 server sends the entire message here>
		S: .

*/

type RetrCommand struct{}

func (cmd RetrCommand) Run(c *Client, args []string) (int, error) {
	if c.currentState != STATE_TRANSACTION {
		return 0, ErrInvalidState
	}
	if len(args) == 0 {
		c.printer.Err("Missing argument for RETR command")
		return 0, fmt.Errorf("Missing argument for RETR called by user %s", c.user.Username())
	}

	msgId, err := strconv.Atoi(args[0])
	if err != nil {
		c.printer.Err("Invalid argument: %s", args[0])
		return 0, fmt.Errorf("Invalid argument for RETR given by user %s: %v", c.user.Username(), err)
	}

	message, err := c.backend.Retr(c.user, msgId)
	if err != nil {
		return 0, fmt.Errorf("Error calling 'RETR %d' for user %s: %v", msgId, c.user.Username(), err)
	}
	lines := strings.Split(message, "\n")
	c.printer.Ok("")
	c.printer.MultiLine(lines)
	return STATE_TRANSACTION, nil
}

/*

DELE msg

	Arguments:
		a message-number (required) which may NOT refer to a
		message marked as deleted

	Restrictions:
		may only be given in the TRANSACTION state
	Discussion:
		The POP3 server marks the message as deleted.  Any future
		reference to the message-number associated with the message
		in a POP3 command generates an error.  The POP3 server does
		not actually delete the message until the POP3 session
		enters the UPDATE state.

	Possible Responses:
		+OK message deleted
		-ERR no such message

	Examples:
		C: DELE 1
		S: +OK message 1 deleted
		...
		C: DELE 2
		S: -ERR message 2 already deleted

*/

type DeleCommand struct{}

func (cmd DeleCommand) Run(c *Client, args []string) (int, error) {
	if c.currentState != STATE_TRANSACTION {
		return 0, ErrInvalidState
	}
	if len(args) == 0 {
		c.printer.Err("Missing argument for DELE command")
		return 0, fmt.Errorf("Missing argument for DELE called by user %s", c.user.Username())
	}

	msgId, err := strconv.Atoi(args[0])
	if err != nil {
		c.printer.Err("Invalid argument: %s", args[0])
		return 0, fmt.Errorf("Invalid argument for DELE given by user %s: %v", c.user.Username(), err)
	}
	err = c.backend.Dele(c.user, msgId)
	if err != nil {
		return 0, fmt.Errorf("Error calling 'DELE %d' for user %s: %v", msgId, c.user.Username(), err)
	}

	c.printer.Ok("Message %d deleted", msgId)

	return STATE_TRANSACTION, nil
}

/*
NOOP

	Arguments: none

	Restrictions:
		may only be given in the TRANSACTION state

	Discussion:
		The POP3 server does nothing, it merely replies with a
		positive response.

	Possible Responses:
		+OK

	Examples:
		C: NOOP
		S: +OK


RSET

	Arguments: none

	Restrictions:
		may only be given in the TRANSACTION state

	Discussion:
		If any messages have been marked as deleted by the POP3
		server, they are unmarked.  The POP3 server then replies
		with a positive response.

	Possible Responses:
		+OK

	Examples:
		C: RSET
		S: +OK maildrop has 2 messages (320 octets)
*/

type NoopCommand struct{}

func (cmd NoopCommand) Run(c *Client, args []string) (int, error) {
	if c.currentState != STATE_TRANSACTION {
		return 0, ErrInvalidState
	}
	c.printer.Ok("")
	return STATE_TRANSACTION, nil
}

/*
RSET

	Arguments: none

	Restrictions:
		may only be given in the TRANSACTION state

	Discussion:
		If any messages have been marked as deleted by the POP3
		server, they are unmarked.  The POP3 server then replies
		with a positive response.

	Possible Responses:
		+OK

	Examples:
		C: RSET
		S: +OK maildrop has 2 messages (320 octets)
*/

type RsetCommand struct{}

func (cmd RsetCommand) Run(c *Client, args []string) (int, error) {
	if c.currentState != STATE_TRANSACTION {
		return 0, ErrInvalidState
	}
	err := c.backend.Rset(c.user)
	if err != nil {
		return 0, fmt.Errorf("Error calling 'RSET' for user %s: %v", c.user.Username(), err)
	}

	c.printer.Ok("")

	return STATE_TRANSACTION, nil
}

/*
UIDL [msg]

	Arguments:
		a message-number (optional), which, if present, may NOT
		refer to a message marked as deleted

	Restrictions:
		may only be given in the TRANSACTION state.

	Discussion:
		If an argument was given and the POP3 server issues a positive
		response with a line containing information for that message.
		This line is called a "unique-id listing" for that message.

		If no argument was given and the POP3 server issues a positive
		response, then the response given is multi-line.  After the
		initial +OK, for each message in the maildrop, the POP3 server
		responds with a line containing information for that message.
		This line is called a "unique-id listing" for that message.

		In order to simplify parsing, all POP3 servers are required to
		use a certain format for unique-id listings.  A unique-id
		listing consists of the message-number of the message,
		followed by a single space and the unique-id of the message.
		No information follows the unique-id in the unique-id listing.

		The unique-id of a message is an arbitrary server-determined
		string, consisting of one to 70 characters in the range 0x21
		to 0x7E, which uniquely identifies a message within a
		maildrop and which persists across sessions.  This
		persistence is required even if a session ends without
		entering the UPDATE state.  The server should never reuse an
		unique-id in a given maildrop, for as long as the entity
		using the unique-id exists.

		Note that messages marked as deleted are not listed.

		While it is generally preferable for server implementations
		to store arbitrarily assigned unique-ids in the maildrop,
		this specification is intended to permit unique-ids to be
		calculated as a hash of the message.  Clients should be able
		to handle a situation where two identical copies of a
		message in a maildrop have the same unique-id.

	Possible Responses:
		+OK unique-id listing follows
		-ERR no such message

	Examples:
		C: UIDL
		S: +OK
		S: 1 whqtswO00WBw418f9t5JxYwZ
		S: 2 QhdPYR:00WBw1Ph7x7
		S: .
			...
		C: UIDL 2
		S: +OK 2 QhdPYR:00WBw1Ph7x7
			...
		C: UIDL 3
		S: -ERR no such message, only 2 messages in maildrop
*/

type UidlCommand struct{}

func (cmd UidlCommand) Run(c *Client, args []string) (int, error) {
	if c.currentState != STATE_TRANSACTION {
		return 0, ErrInvalidState
	}

	if len(args) > 0 {
		msgId, err := strconv.Atoi(args[0])
		if err != nil {
			c.printer.Err("Invalid argument: %s", args[0])
			return 0, fmt.Errorf("Invalid argument for UIDL given by user %s: %v", c.user.Username(), err)
		}
		exists, uid, err := c.backend.UidlMessage(c.user, msgId)
		if err != nil {
			return 0, fmt.Errorf("Error calling 'UIDL %d' for user %s: %v", msgId, c.user.Username(), err)
		}
		if !exists {
			c.printer.Err("no such message")
			return STATE_TRANSACTION, nil
		}
		c.printer.Ok("%d %s", msgId, uid)
	} else {
		uids, err := c.backend.Uidl(c.user)
		if err != nil {
			return 0, fmt.Errorf("Error calling UIDL for user %s: %v", c.user.Username(), err)
		}
		c.printer.Ok("%d messages", len(uids))
		uidsList := make([]string, len(uids))
		for i, uid := range uids {
			uidsList[i] = fmt.Sprintf("%d %s", i+1, uid)
		}
		c.printer.MultiLine(uidsList)
	}

	return STATE_TRANSACTION, nil
}

/*
Defined in https://www.ietf.org/rfc/rfc2449.txt

CAPA

	Arguments:
		none

	Restrictions:
		none

	Discussion:
		An -ERR response indicates the capability command is not
		implemented and the client will have to probe for
		capabilities as before.

		An +OK response is followed by a list of capabilities, one
		per line.  Each capability name MAY be followed by a single
		space and a space-separated list of parameters.  Each
		capability line is limited to 512 octets (including the
		CRLF).  The capability list is terminated by a line
		containing a termination octet (".") and a CRLF pair.

		Possible Responses:
			+OK -ERR

		Examples:
			C: CAPA
			S: +OK Capability list follows
			S: TOP
			S: USER
			S: SASL CRAM-MD5 KERBEROS_V4
			S: RESP-CODES
			S: LOGIN-DELAY 900
			S: PIPELINING
			S: EXPIRE 60
			S: UIDL
			S: IMPLEMENTATION Shlemazle-Plotz-v302
			S: .
*/

type CapaCommand struct{}

func (cmd CapaCommand) Run(c *Client, args []string) (int, error) {
	c.printer.Ok("")
	var commands []string
	commands = []string{"USER", "UIDL", "TOP"}

	c.printer.MultiLine(commands)

	return c.currentState, nil
}

/*
TOP msg n

	Arguments:
		a message-number (required) which may NOT refer to to a
		message marked as deleted, and a non-negative number
		of lines (required)

	Restrictions:
		may only be given in the TRANSACTION state

	Discussion:
		If the POP3 server issues a positive response, then the
		response given is multi-line.  After the initial +OK, the
		POP3 server sends the headers of the message, the blank
		line separating the headers from the body, and then the
		number of lines of the indicated message's body, being
		careful to byte-stuff the termination character (as with
		all multi-line responses).

		Note that if the number of lines requested by the POP3
		client is greater than than the number of lines in the
		body, then the POP3 server sends the entire message.

	Possible Responses:
		+OK top of message follows
		-ERR no such message

	Examples:
		C: TOP 1 10
		S: +OK
		S: <the POP3 server sends the headers of the
		message, a blank line, and the first 10 lines
		of the body of the message>
		S: .
		...
		C: TOP 100 3
		S: -ERR no such message
*/

type TopCommand struct{}

func (cmd TopCommand) Run(c *Client, args []string) (int, error) {
	if c.currentState != STATE_TRANSACTION {
		return 0, ErrInvalidState
	}

	if len(args) != 2 {
		return 0, fmt.Errorf("Invalid number of arguments for TOP for user %s", c.user.Username())
	}

	msgId, err := strconv.Atoi(args[0])
	if err != nil {
		c.printer.Err("Invalid argument: %s", args[0])
		return 0, fmt.Errorf("Invalid argument for TOP given by user %s: %v", c.user.Username(), err)
	}

	n, err := strconv.Atoi(args[1])
	if err != nil {
		c.printer.Err("Invalid argument: %s", args[1])
		return 0, fmt.Errorf("Invalid argument for TOP given by user %s: %v", c.user.Username(), err)
	}

	lines, err := c.backend.Top(c.user, msgId, n)
	if err != nil {
		return 0, fmt.Errorf("Error calling 'TOP %d %d' for user %s: %v", msgId, n, c.user.Username(), err)
	}
	c.printer.Ok("")
	c.printer.MultiLine(lines)
	return STATE_TRANSACTION, nil
}
