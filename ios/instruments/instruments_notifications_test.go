package instruments

import (
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	dtx "github.com/danielpaulus/go-ios/ios/dtx_codec"
)

type countingCloser struct {
	closeCalls atomic.Int32
}

func (c *countingCloser) Close() error {
	c.closeCalls.Add(1)
	return nil
}

func TestChannelDispatcherCloseReleasesConnectionOnce(t *testing.T) {
	closer := &countingCloser{}
	dispatcher := &channelDispatcher{
		messageChannel: make(chan dtx.Message),
		closeChannel:   make(chan struct{}),
		connection:     closer,
	}

	if err := dispatcher.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := dispatcher.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if got := closer.closeCalls.Load(); got != 1 {
		t.Fatalf("connection Close calls = %d, want 1", got)
	}
	if _, err := dispatcher.Receive(); err != io.EOF {
		t.Fatalf("Receive() error = %v, want EOF", err)
	}
}

func TestChannelDispatcherCloseUnblocksDispatch(t *testing.T) {
	dispatcher := &channelDispatcher{
		messageChannel: make(chan dtx.Message),
		closeChannel:   make(chan struct{}),
	}
	done := make(chan struct{})
	go func() {
		dispatcher.Dispatch(dtx.Message{})
		close(done)
	}()

	if err := dispatcher.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Dispatch remained blocked after Close")
	}
}

func TestChannelDispatcherReceiveStopsOnDTXEOF(t *testing.T) {
	connectionClosed := make(chan struct{})
	connectionErr := io.EOF
	dispatcher := &channelDispatcher{
		messageChannel:   make(chan dtx.Message),
		closeChannel:     make(chan struct{}),
		connectionClosed: connectionClosed,
		connectionErr:    func() error { return connectionErr },
	}
	result := make(chan error, 1)
	go func() {
		_, err := dispatcher.Receive()
		result <- err
	}()
	close(connectionClosed)

	select {
	case err := <-result:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("Receive() error = %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Receive remained blocked after DTX EOF")
	}
}
