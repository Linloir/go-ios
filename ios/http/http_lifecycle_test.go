package http

import (
	"errors"
	"sync/atomic"
	"testing"
)

type failingReadWriteCloser struct {
	closeCalls atomic.Int32
}

func (c *failingReadWriteCloser) Read([]byte) (int, error) {
	return 0, errors.New("unexpected read")
}

func (c *failingReadWriteCloser) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func (c *failingReadWriteCloser) Close() error {
	c.closeCalls.Add(1)
	return nil
}

func TestNewHttpConnectionClosesTransportOnSetupError(t *testing.T) {
	rwc := &failingReadWriteCloser{}
	connection, err := NewHttpConnection(rwc)
	if err == nil {
		t.Fatal("NewHttpConnection() error = nil, want setup error")
	}
	if connection != nil {
		t.Fatalf("NewHttpConnection() connection = %v, want nil", connection)
	}
	if got := rwc.closeCalls.Load(); got != 1 {
		t.Fatalf("underlying Close calls = %d, want 1", got)
	}
}
