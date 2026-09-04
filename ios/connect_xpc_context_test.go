package ios

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goioshttp "github.com/danielpaulus/go-ios/ios/http"
	"github.com/danielpaulus/go-ios/ios/xpc"
	"golang.org/x/net/http2"
)

const testHTTP2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

type observedXPCTransport struct {
	net.Conn

	mu         sync.Mutex
	deadlines  []time.Time
	closeCalls atomic.Int32
}

func (c *observedXPCTransport) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, deadline)
	c.mu.Unlock()
	return c.Conn.SetDeadline(deadline)
}

func (c *observedXPCTransport) Close() error {
	c.closeCalls.Add(1)
	return c.Conn.Close()
}

func (c *observedXPCTransport) lastDeadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.deadlines) == 0 {
		return time.Time{}
	}
	return c.deadlines[len(c.deadlines)-1]
}

func peerHTTP2Handshake(conn net.Conn) (*http2.Framer, error) {
	preface := make([]byte, len(testHTTP2ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		return nil, err
	}
	if string(preface) != testHTTP2ClientPreface {
		return nil, errors.New("invalid HTTP/2 client preface")
	}
	framer := http2.NewFramer(conn, conn)
	frame, err := framer.ReadFrame()
	if err != nil {
		return nil, err
	}
	if _, ok := frame.(*http2.SettingsFrame); !ok {
		return nil, errors.New("first client frame was not SETTINGS")
	}
	frame, err = framer.ReadFrame()
	if err != nil {
		return nil, err
	}
	if _, ok := frame.(*http2.WindowUpdateFrame); !ok {
		return nil, errors.New("second client frame was not WINDOW_UPDATE")
	}
	if err := framer.WriteSettings(); err != nil {
		return nil, err
	}
	frame, err = framer.ReadFrame()
	if err != nil {
		return nil, err
	}
	settings, ok := frame.(*http2.SettingsFrame)
	if !ok || !settings.IsAck() {
		return nil, errors.New("client did not acknowledge peer SETTINGS")
	}
	return framer, nil
}

func newTestHTTPConnection(t *testing.T, client net.Conn) *goioshttp.HttpConnection {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	h, err := goioshttp.NewHttpConnectionContext(ctx, client)
	if err != nil {
		t.Fatalf("NewHttpConnectionContext() error = %v", err)
	}
	return h
}

func TestCreateXpcConnectionContextTimesOutSilentInitializationPeer(t *testing.T) {
	client, server := net.Pipe()
	transport := &observedXPCTransport{Conn: client}
	peerSawInitialMessage := make(chan struct{})
	peerClosed := make(chan error, 1)
	peerHandshake := make(chan error, 1)
	go func() {
		defer server.Close()
		framer, err := peerHTTP2Handshake(server)
		peerHandshake <- err
		if err != nil {
			return
		}
		for {
			frame, err := framer.ReadFrame()
			if err != nil {
				peerClosed <- err
				return
			}
			if data, ok := frame.(*http2.DataFrame); ok && data.StreamID == uint32(goioshttp.ClientServer) {
				close(peerSawInitialMessage)
				_, err := framer.ReadFrame()
				peerClosed <- err
				return
			}
		}
	}()

	h := newTestHTTPConnection(t, transport)
	if err := <-peerHandshake; err != nil {
		t.Fatalf("peer HTTP/2 handshake error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		conn, err := CreateXpcConnectionContext(ctx, h)
		if conn != nil {
			_ = conn.Close()
		}
		result <- err
	}()

	select {
	case <-peerSawInitialMessage:
	case <-time.After(time.Second):
		t.Fatal("peer did not receive the initial RemoteXPC message")
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("CreateXpcConnectionContext() error = %v, want %v", err, context.DeadlineExceeded)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CreateXpcConnectionContext did not stop for a silent peer")
	}
	if got := transport.closeCalls.Load(); got != 1 {
		t.Fatalf("underlying Close calls = %d, want 1", got)
	}
	select {
	case err := <-peerClosed:
		if err == nil {
			t.Fatal("peer read unexpectedly succeeded after initialization timeout")
		}
	case <-time.After(time.Second):
		t.Fatal("peer transport was not closed after initialization timeout")
	}
}

func TestCreateXpcConnectionContextClearsDeadlineAndDetachesContext(t *testing.T) {
	client, server := net.Pipe()
	transport := &observedXPCTransport{Conn: client}
	peerHandshake := make(chan error, 1)
	peerReceivedPostInitializationMessage := make(chan struct{})
	peerDone := make(chan error, 1)
	go func() {
		defer server.Close()
		framer, err := peerHTTP2Handshake(server)
		peerHandshake <- err
		if err != nil {
			return
		}
		responses := 0
		for {
			frame, err := framer.ReadFrame()
			if err != nil {
				peerDone <- err
				return
			}
			data, ok := frame.(*http2.DataFrame)
			if !ok {
				continue
			}
			if responses == 3 {
				close(peerReceivedPostInitializationMessage)
				return
			}
			var encoded bytes.Buffer
			if err := xpc.EncodeMessage(&encoded, xpc.Message{
				Flags: xpc.AlwaysSetFlag,
				Body:  map[string]interface{}{},
				Id:    uint64(responses),
			}); err != nil {
				peerDone <- err
				return
			}
			if err := framer.WriteData(data.StreamID, false, encoded.Bytes()); err != nil {
				peerDone <- err
				return
			}
			responses++
		}
	}()

	h := newTestHTTPConnection(t, transport)
	if err := <-peerHandshake; err != nil {
		t.Fatalf("peer HTTP/2 handshake error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	connection, err := CreateXpcConnectionContext(ctx, h)
	if err != nil {
		cancel()
		t.Fatalf("CreateXpcConnectionContext() error = %v", err)
	}
	if deadline := transport.lastDeadline(); !deadline.IsZero() {
		cancel()
		_ = connection.Close()
		t.Fatalf("last transport deadline = %v, want cleared deadline", deadline)
	}

	// The setup context no longer owns the established XPC connection.
	cancel()
	if err := connection.Send(map[string]interface{}{"after": "setup context"}); err != nil {
		_ = connection.Close()
		t.Fatalf("Send() after setup context cancellation error = %v", err)
	}
	select {
	case <-peerReceivedPostInitializationMessage:
	case err := <-peerDone:
		_ = connection.Close()
		t.Fatalf("peer failed before post-initialization message: %v", err)
	case <-time.After(time.Second):
		_ = connection.Close()
		t.Fatal("peer did not receive post-initialization message")
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := transport.closeCalls.Load(); got != 1 {
		t.Fatalf("underlying Close calls = %d, want 1", got)
	}
}
