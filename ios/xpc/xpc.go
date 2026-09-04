// Package xpc contains a connection stuct and the codec for the xpc protocol.
// The xpc protocol is used to communicate with services on iOS17+ devices.
package xpc

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

// Connection represents a http2 based connection to an XPC service on an iOS17 device.
type Connection struct {
	connectionCloser io.Closer
	msgID            uint64
	clientServer     io.ReadWriter
	serverClient     io.ReadWriter

	sendMu             sync.Mutex
	clientServerReadMu sync.Mutex
	serverClientReadMu sync.Mutex
	closed             atomic.Bool
	closeOnce          sync.Once
	closeErr           error
}

// New creates a new connection to an XPC service on an iOS17 device.
func New(clientServer io.ReadWriter, serverClient io.ReadWriter, closer io.Closer) (*Connection, error) {
	return &Connection{
		connectionCloser: closer,
		msgID:            1,
		clientServer:     clientServer,
		serverClient:     serverClient,
	}, nil
}

func (c *Connection) ReceiveOnServerClientStream() (map[string]interface{}, error) {
	c.serverClientReadMu.Lock()
	defer c.serverClientReadMu.Unlock()

	if c.closed.Load() {
		return nil, io.ErrClosedPipe
	}
	msg, err := DecodeMessage(c.serverClient)
	if err != nil {
		// A decode error leaves the byte-stream boundary unknown. Continuing on
		// this transport could interpret a tail fragment as a fresh XPC message.
		_ = c.Close()
		return nil, fmt.Errorf("ReceiveOnServerClientStream: %w", err)
	}
	return msg.Body, nil
}

func (c *Connection) ReceiveOnClientServerStream() (map[string]interface{}, error) {
	c.clientServerReadMu.Lock()
	defer c.clientServerReadMu.Unlock()

	return c.receiveOnStream(c.clientServer)
}

func (c *Connection) receiveOnStream(r io.Reader) (map[string]interface{}, error) {
	if c.closed.Load() {
		return nil, io.ErrClosedPipe
	}
	msg, err := DecodeMessage(r)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("receiveOnStream: %w", err)
	}
	return msg.Body, nil
}

// Send sends the passed data as XPC message.
// Additional flags can be passed via the flags argument (the default ones are AlwaysSetFlag and if data != nil DataFlag)
func (c *Connection) Send(data map[string]interface{}, flags ...uint32) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	if c.closed.Load() {
		return io.ErrClosedPipe
	}

	f := AlwaysSetFlag
	if data != nil {
		f |= DataFlag
	}
	for _, flag := range flags {
		f |= flag
	}
	msg := Message{
		Flags: f,
		Body:  data,
		Id:    c.msgID,
	}
	encoded, err := encodeMessage(msg)
	if err != nil {
		return err
	}
	// A message ID belongs to the send attempt, even if the transport fails
	// part-way through it. Reusing an ID after a partial write could make the
	// peer mistake the retry for the original message.
	c.msgID++
	if err := writeAll(c.clientServer, encoded); err != nil {
		// Once any part of a frame reaches the wire, the byte stream cannot be
		// resynchronized safely. Terminal-close it instead of allowing another
		// message to be appended to a truncated frame.
		_ = c.Close()
		return fmt.Errorf("Send: failed to write encoded message: %w", err)
	}
	return nil
}

func (c *Connection) Close() error {
	c.closeOnce.Do(func() {
		// Do not wait for sendMu here: closing the underlying transport is what
		// unblocks a Send stalled on a silent or disconnected peer.
		c.closed.Store(true)
		if c.connectionCloser != nil {
			c.closeErr = c.connectionCloser.Close()
		}
	})
	return c.closeErr
}
