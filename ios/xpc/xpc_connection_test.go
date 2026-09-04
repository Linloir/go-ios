package xpc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type yieldingReadWriter struct {
	mu   sync.Mutex
	data []byte
}

func (w *yieldingReadWriter) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (w *yieldingReadWriter) Write(p []byte) (int, error) {
	// Lock one byte at a time so concurrent callers would deterministically be
	// able to interleave complete RemoteXPC messages without Connection.sendMu.
	for _, b := range p {
		w.mu.Lock()
		w.data = append(w.data, b)
		w.mu.Unlock()
		runtime.Gosched()
	}
	return len(p), nil
}

func (w *yieldingReadWriter) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.data...)
}

type countingCloser struct {
	calls atomic.Int32
	err   error
}

func (c *countingCloser) Close() error {
	c.calls.Add(1)
	return c.err
}

func TestConnectionConcurrentSendSerializesMessagesAndIncrementsIDs(t *testing.T) {
	stream := &yieldingReadWriter{}
	connection, err := New(stream, bytes.NewBuffer(nil), nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	const sendCount = 64
	start := make(chan struct{})
	errs := make(chan error, sendCount)
	var wg sync.WaitGroup
	for i := 0; i < sendCount; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- connection.Send(map[string]interface{}{"sequence": uint64(i)})
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Send() error = %v", err)
		}
	}

	encoded := bytes.NewReader(stream.Bytes())
	for wantID := uint64(1); wantID <= sendCount; wantID++ {
		var magic uint32
		if err := binary.Read(encoded, binary.LittleEndian, &magic); err != nil {
			t.Fatalf("message %d magic: %v", wantID, err)
		}
		if magic != wrapperMagic {
			t.Fatalf("message %d magic = %#x, want %#x", wantID, magic, wrapperMagic)
		}
		var header wrapperHeader
		if err := binary.Read(encoded, binary.LittleEndian, &header); err != nil {
			t.Fatalf("message %d header: %v", wantID, err)
		}
		if header.MsgId != wantID {
			t.Fatalf("message ID = %d, want %d", header.MsgId, wantID)
		}
		if header.BodyLen > uint64(encoded.Len()) {
			t.Fatalf("message %d body length %d exceeds remaining %d", wantID, header.BodyLen, encoded.Len())
		}
		if _, err := io.CopyN(io.Discard, encoded, int64(header.BodyLen)); err != nil {
			t.Fatalf("message %d body: %v", wantID, err)
		}
	}
	if encoded.Len() != 0 {
		t.Fatalf("unexpected %d trailing encoded bytes", encoded.Len())
	}
}

func TestConnectionLocalEncodeFailureDoesNotConsumeMessageID(t *testing.T) {
	stream := &yieldingReadWriter{}
	connection, err := New(stream, bytes.NewBuffer(nil), nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := connection.Send(map[string]interface{}{"unsupported": make(chan int)}); err == nil {
		t.Fatal("Send() unsupported body error = nil")
	}
	if err := connection.Send(map[string]interface{}{"valid": true}); err != nil {
		t.Fatalf("Send() valid body error = %v", err)
	}

	encoded := bytes.NewReader(stream.Bytes())
	var magic uint32
	if err := binary.Read(encoded, binary.LittleEndian, &magic); err != nil {
		t.Fatal(err)
	}
	var header wrapperHeader
	if err := binary.Read(encoded, binary.LittleEndian, &header); err != nil {
		t.Fatal(err)
	}
	if header.MsgId != 1 {
		t.Fatalf("first transmitted message ID = %d, want 1", header.MsgId)
	}
}

type partialFailureTransport struct {
	closeCalls atomic.Int32
	err        error
}

func (t *partialFailureTransport) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (t *partialFailureTransport) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, t.err
	}
	return 1, t.err
}

func (t *partialFailureTransport) Close() error {
	t.closeCalls.Add(1)
	return nil
}

func TestConnectionPartialWriteFailureIsTerminal(t *testing.T) {
	wantErr := errors.New("partial write sentinel")
	transport := &partialFailureTransport{err: wantErr}
	connection, err := New(transport, transport, transport)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := connection.Send(map[string]interface{}{"partial": true}); !errors.Is(err, wantErr) {
		t.Fatalf("Send() error = %v, want %v", err, wantErr)
	}
	if got := transport.closeCalls.Load(); got != 1 {
		t.Fatalf("underlying Close calls = %d, want 1", got)
	}
	if err := connection.Send(map[string]interface{}{"after": "failure"}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Send() after partial failure error = %v, want %v", err, io.ErrClosedPipe)
	}
}

func TestConnectionCloseIsIdempotent(t *testing.T) {
	wantErr := errors.New("close sentinel")
	closer := &countingCloser{err: wantErr}
	connection, err := New(bytes.NewBuffer(nil), bytes.NewBuffer(nil), closer)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	const callers = 32
	results := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- connection.Close()
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if !errors.Is(err, wantErr) {
			t.Fatalf("Close() error = %v, want %v", err, wantErr)
		}
	}
	if got := closer.calls.Load(); got != 1 {
		t.Fatalf("underlying Close calls = %d, want 1", got)
	}
	if err := connection.Send(map[string]interface{}{"after": "close"}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Send() after Close error = %v, want %v", err, io.ErrClosedPipe)
	}
}

type blockingReadWriteCloser struct {
	writeStarted chan struct{}
	closed       chan struct{}
	startOnce    sync.Once
	closeOnce    sync.Once
}

func newBlockingReadWriteCloser() *blockingReadWriteCloser {
	return &blockingReadWriteCloser{
		writeStarted: make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

func (c *blockingReadWriteCloser) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.ErrClosedPipe
}

func (c *blockingReadWriteCloser) Write([]byte) (int, error) {
	c.startOnce.Do(func() { close(c.writeStarted) })
	<-c.closed
	return 0, io.ErrClosedPipe
}

func (c *blockingReadWriteCloser) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func TestConnectionCloseUnblocksStalledSend(t *testing.T) {
	transport := newBlockingReadWriteCloser()
	connection, err := New(transport, transport, transport)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	sendDone := make(chan error, 1)
	go func() {
		sendDone <- connection.Send(map[string]interface{}{"blocked": true})
	}()
	select {
	case <-transport.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("Send did not reach the transport")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- connection.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close blocked behind a stalled Send")
	}
	select {
	case err := <-sendDone:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("Send() error = %v, want %v", err, io.ErrClosedPipe)
		}
	case <-time.After(time.Second):
		t.Fatal("stalled Send was not unblocked by Close")
	}
}

func TestConnectionDecodeFailureIsTerminalOnBothReceiveStreams(t *testing.T) {
	tests := []struct {
		name    string
		receive func(*Connection) (map[string]interface{}, error)
	}{
		{name: "client-server", receive: (*Connection).ReceiveOnClientServerStream},
		{name: "server-client", receive: (*Connection).ReceiveOnServerClientStream},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			closer := &countingCloser{}
			truncated := bytes.NewBuffer([]byte{0x92, 0x0b})
			connection, err := New(truncated, truncated, closer)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if _, err := tt.receive(connection); err == nil {
				t.Fatal("Receive() error = nil, want decode error")
			}
			if got := closer.calls.Load(); got != 1 {
				t.Fatalf("underlying Close calls = %d, want 1", got)
			}
			if _, err := tt.receive(connection); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("second Receive() error = %v, want %v", err, io.ErrClosedPipe)
			}
			if err := connection.Send(map[string]interface{}{"after": "decode failure"}); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("Send() after decode failure error = %v, want %v", err, io.ErrClosedPipe)
			}
			if got := closer.calls.Load(); got != 1 {
				t.Fatalf("underlying Close calls after reuse = %d, want 1", got)
			}
		})
	}
}
