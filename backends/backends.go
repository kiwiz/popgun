package backends

import (
	"fmt"
	"net"
)

type User interface {
  Username() string
}

// DummyUser is a fake user interface implementation used for tests
type DummyUser struct {
}

func (u DummyUser) Username() string {
	return "user"
}

// DummyAuthorizator is a fake authorizator interface implementation used for tests
type DummyAuthorizator struct {
}

// Authorize user for given username and password.
func (a DummyAuthorizator) Authorize(conn net.Conn, username, password string) (User, error) {
	return &DummyUser{}, nil
}

// DummyBackend is a fake backend interface implementation used for test
type DummyBackend struct {
}

// Returns total message count and total mailbox size in bytes (octets).
// Deleted messages are ignored.
func (b DummyBackend) Stat(user User) (messages, octets int, err error) {
	return 5, 50, nil
}

// List of sizes of all messages in bytes (octets)
func (b DummyBackend) List(user User) (octets []int, err error) {
	return []int{10, 10, 10, 10, 10}, nil
}

// Returns whether message exists and if yes, then return size of the message in bytes (octets)
func (b DummyBackend) ListMessage(user User, msgId int) (exists bool, octets int, err error) {
	if msgId > 4 {
		return false, 0, nil
	}
	return true, 10, nil
}

// Retrieve whole message by ID - note that message ID is a message position returned
// by List() function, so be sure to keep that order unchanged while client is connected
// See Lock() function for more details
func (b DummyBackend) Retr(user User, msgId int) (message string, err error) {
	return "this is dummy message", nil
}

// Delete message by message ID - message should be just marked as deleted until
// Update() is called. Be aware that after Dele() is called, functions like List() etc.
// should ignore all these messages even if Update() hasn't been called yet
func (b DummyBackend) Dele(user User, msgId int) error {
	return nil
}

// Undelete all messages marked as deleted in single connection
func (b DummyBackend) Rset(user User) error {
	return nil
}

// List of unique IDs of all message, similar to List(), but instead of size there
// is a unique ID which persists the same across all connections. Uid (unique id) is
// used to allow client to be able to keep messages on the server.
func (b DummyBackend) Uidl(user User) (uids []string, err error) {
	return []string{"1", "2", "3", "4", "5"}, nil
}

// Similar to ListMessage, but returns unique ID by message ID instead of size.
func (b DummyBackend) UidlMessage(user User, msgId int) (exists bool, uid string, err error) {
	if msgId > 4 {
		return false, "", nil
	}
	return true, fmt.Sprintf("%d", msgId+1), nil
}

// Write all changes to persistent storage, i.e. delete all messages marked as deleted.
func (b DummyBackend) Update(user User) error {
	return nil
}

// If the POP3 server issues a positive response, then the
// response given is multi-line.  After the initial +OK, the
// POP3 server sends the headers of the message, the blank
// line separating the headers from the body, and then the
// number of lines of the indicated message's body, being
// careful to byte-stuff the termination character (as with
// all multi-line responses).
// Note that if the number of lines requested by the POP3
// client is greater than than the number of lines in the
// body, then the POP3 server sends the entire message.
func (b DummyBackend) Top(user User, msgId int, n int) (lines []string, err error) {
	return nil, nil
}

// Lock is called immediately after client is connected. The best way what to use Lock() for
// is to read all the messages into cache after client is connected. If another user
// tries to lock the storage, you should return an error to avoid data race.
func (b DummyBackend) Lock(user User) error {
	return nil
}

// Release lock on storage, Unlock() is called after client is disconnected.
func (b DummyBackend) Unlock(user User) error {
	return nil
}
