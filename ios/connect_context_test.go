package ios

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type blockedConnectStage string

const (
	blockDialLockdown    blockedConnectStage = "dial lockdown"
	blockReadPair        blockedConnectStage = "read pair record"
	blockConnectLockdown blockedConnectStage = "connect lockdown"
	blockStartSession    blockedConnectStage = "start session"
	blockSessionSSL      blockedConnectStage = "session SSL"
	blockStartService    blockedConnectStage = "start service"
	blockStopSession     blockedConnectStage = "stop session"
	blockDialService     blockedConnectStage = "dial service"
	blockConnectService  blockedConnectStage = "connect service"
	blockServiceSSL      blockedConnectStage = "service SSL"
)

type contextStageDeviceConnection struct {
	mu       sync.Mutex
	input    *bytes.Reader
	blocked  chan struct{}
	closed   chan struct{}
	blockOne sync.Once
	closeOne sync.Once
	blockSSL bool
}

func newContextStageDeviceConnection(input []byte, blockSSL bool) *contextStageDeviceConnection {
	return &contextStageDeviceConnection{
		input:    bytes.NewReader(input),
		blocked:  make(chan struct{}),
		closed:   make(chan struct{}),
		blockSSL: blockSSL,
	}
}

func (c *contextStageDeviceConnection) Read(p []byte) (int, error) {
	c.mu.Lock()
	if c.input.Len() > 0 {
		n, err := c.input.Read(p)
		c.mu.Unlock()
		return n, err
	}
	c.mu.Unlock()
	c.blockOne.Do(func() { close(c.blocked) })
	<-c.closed
	return 0, net.ErrClosed
}

func (c *contextStageDeviceConnection) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
		return len(p), nil
	}
}

func (c *contextStageDeviceConnection) Close() error {
	c.closeOne.Do(func() { close(c.closed) })
	return nil
}

func (c *contextStageDeviceConnection) Send(message []byte) error {
	_, err := c.Write(message)
	return err
}

func (c *contextStageDeviceConnection) Reader() io.Reader { return c }
func (c *contextStageDeviceConnection) Writer() io.Writer { return c }

func (c *contextStageDeviceConnection) EnableSessionSsl(PairRecord) error {
	if !c.blockSSL {
		return nil
	}
	c.blockOne.Do(func() { close(c.blocked) })
	<-c.closed
	return net.ErrClosed
}

func (c *contextStageDeviceConnection) EnableSessionSslServerMode(PairRecord) error {
	return c.EnableSessionSsl(PairRecord{})
}

func (c *contextStageDeviceConnection) EnableSessionSslHandshakeOnly(PairRecord) error {
	return c.EnableSessionSsl(PairRecord{})
}

func (c *contextStageDeviceConnection) EnableSessionSslServerModeHandshakeOnly(PairRecord) error {
	return c.EnableSessionSsl(PairRecord{})
}

func (c *contextStageDeviceConnection) DisableSessionSSL()  {}
func (c *contextStageDeviceConnection) Conn() net.Conn      { return c }
func (c *contextStageDeviceConnection) LocalAddr() net.Addr { return contextStageAddr("local") }
func (c *contextStageDeviceConnection) RemoteAddr() net.Addr {
	return contextStageAddr("remote")
}
func (c *contextStageDeviceConnection) SetDeadline(time.Time) error      { return nil }
func (c *contextStageDeviceConnection) SetReadDeadline(time.Time) error  { return nil }
func (c *contextStageDeviceConnection) SetWriteDeadline(time.Time) error { return nil }

type contextStageAddr string

func (a contextStageAddr) Network() string { return "test" }
func (a contextStageAddr) String() string  { return string(a) }

type sslBoundaryRawConn struct {
	closed   chan struct{}
	closeOne sync.Once
}

func newSSLBoundaryRawConn() *sslBoundaryRawConn {
	return &sslBoundaryRawConn{closed: make(chan struct{})}
}

func (c *sslBoundaryRawConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *sslBoundaryRawConn) Write([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *sslBoundaryRawConn) Close() error {
	c.closeOne.Do(func() { close(c.closed) })
	return nil
}

func (c *sslBoundaryRawConn) LocalAddr() net.Addr              { return contextStageAddr("local") }
func (c *sslBoundaryRawConn) RemoteAddr() net.Addr             { return contextStageAddr("remote") }
func (c *sslBoundaryRawConn) SetDeadline(time.Time) error      { return nil }
func (c *sslBoundaryRawConn) SetReadDeadline(time.Time) error  { return nil }
func (c *sslBoundaryRawConn) SetWriteDeadline(time.Time) error { return nil }

type sslSwapBoundaryDeviceConnection struct {
	*contextStageDeviceConnection
	raw              *sslBoundaryRawConn
	sslStarted       chan struct{}
	sslActive        atomic.Bool
	closeDuringSwap  atomic.Bool
	currentTLSCloser io.Closer
}

func newSSLSwapBoundaryDeviceConnection(input []byte) *sslSwapBoundaryDeviceConnection {
	return &sslSwapBoundaryDeviceConnection{
		contextStageDeviceConnection: newContextStageDeviceConnection(input, false),
		raw:                          newSSLBoundaryRawConn(),
		sslStarted:                   make(chan struct{}),
	}
}

func (c *sslSwapBoundaryDeviceConnection) Read(p []byte) (int, error) {
	c.mu.Lock()
	if c.input.Len() > 0 {
		n, err := c.input.Read(p)
		c.mu.Unlock()
		return n, err
	}
	c.mu.Unlock()
	<-c.raw.closed
	return 0, net.ErrClosed
}

func (c *sslSwapBoundaryDeviceConnection) Write(p []byte) (int, error) {
	select {
	case <-c.raw.closed:
		return 0, net.ErrClosed
	default:
		return len(p), nil
	}
}

func (c *sslSwapBoundaryDeviceConnection) Send(message []byte) error {
	_, err := c.Write(message)
	return err
}

func (c *sslSwapBoundaryDeviceConnection) Reader() io.Reader { return c }
func (c *sslSwapBoundaryDeviceConnection) Writer() io.Writer { return c }
func (c *sslSwapBoundaryDeviceConnection) Conn() net.Conn    { return c.raw }

func (c *sslSwapBoundaryDeviceConnection) EnableSessionSsl(PairRecord) error {
	c.sslActive.Store(true)
	close(c.sslStarted)
	// Model the real boundary after Handshake has begun but before
	// DeviceConnection replaces its current connection with the TLS wrapper.
	<-c.raw.closed
	c.currentTLSCloser = c.raw
	c.sslActive.Store(false)
	return nil
}

func (c *sslSwapBoundaryDeviceConnection) Close() error {
	if c.sslActive.Load() {
		c.closeDuringSwap.Store(true)
	}
	_ = c.contextStageDeviceConnection.Close()
	return c.raw.Close()
}

func muxContextTestFrame(payload interface{}) []byte {
	plistBytes := ToPlistBytes(payload)
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, UsbMuxHeader{
		Length:  uint32(len(plistBytes) + 16),
		Version: 1,
		Request: 8,
		Tag:     1,
	})
	_, _ = buf.Write(plistBytes)
	return buf.Bytes()
}

func lockdownContextTestFrame(payload interface{}) []byte {
	frame, err := NewPlistCodec().Encode(payload)
	if err != nil {
		panic(err)
	}
	return frame
}

func firstContextStageScript(stage blockedConnectStage) ([]byte, bool) {
	var script []byte
	if stage == blockReadPair {
		return script, false
	}
	pair := PairRecord{HostID: "host", SystemBUID: "system"}
	script = append(script, muxContextTestFrame(PairRecordData{PairRecordData: ToPlistBytes(pair)})...)
	if stage == blockConnectLockdown {
		return script, false
	}
	script = append(script, muxContextTestFrame(MuxResponse{MessageType: "Result"})...)
	if stage == blockStartSession {
		return script, false
	}
	sessionSSL := stage == blockSessionSSL
	script = append(script, lockdownContextTestFrame(StartSessionResponse{
		EnableSessionSSL: sessionSSL,
		Request:          "StartSession",
		SessionID:        "session",
	})...)
	if sessionSSL {
		return script, true
	}
	if stage == blockStartService {
		return script, false
	}
	serviceSSL := stage == blockServiceSSL
	script = append(script, lockdownContextTestFrame(StartServiceResponse{
		Port:             1234,
		Request:          "StartService",
		Service:          "test.service",
		EnableServiceSSL: serviceSSL,
	})...)
	if stage == blockStopSession {
		return script, false
	}
	script = append(script, lockdownContextTestFrame(stopSessionResponse{Request: "StopSession"})...)
	return script, false
}

func TestConnectToServiceContextCancelsEveryBlockedSetupStage(t *testing.T) {
	stages := []blockedConnectStage{
		blockDialLockdown,
		blockReadPair,
		blockConnectLockdown,
		blockStartSession,
		blockSessionSSL,
		blockStartService,
		blockStopSession,
		blockDialService,
		blockConnectService,
		blockServiceSSL,
	}

	for _, stage := range stages {
		t.Run(string(stage), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			stageStarted := make(chan struct{})
			var stageStartedOnce sync.Once
			var mu sync.Mutex
			var opened []*contextStageDeviceConnection
			factoryCalls := 0
			factory := func(factoryCtx context.Context) (*UsbMuxConnection, error) {
				factoryCalls++
				if (stage == blockDialLockdown && factoryCalls == 1) || (stage == blockDialService && factoryCalls == 2) {
					stageStartedOnce.Do(func() { close(stageStarted) })
					<-factoryCtx.Done()
					return nil, factoryCtx.Err()
				}

				var script []byte
				var blockSSL bool
				if factoryCalls == 1 {
					script, blockSSL = firstContextStageScript(stage)
				} else if stage == blockServiceSSL {
					script = muxContextTestFrame(MuxResponse{MessageType: "Result"})
					blockSSL = true
				}
				conn := newContextStageDeviceConnection(script, blockSSL)
				mu.Lock()
				opened = append(opened, conn)
				mu.Unlock()
				go func() {
					select {
					case <-conn.blocked:
						stageStartedOnce.Do(func() { close(stageStarted) })
					case <-conn.closed:
					}
				}()
				return NewUsbMuxConnection(conn), nil
			}

			result := make(chan error, 1)
			go func() {
				_, err := connectToServiceContext(ctx, DeviceEntry{DeviceID: 7, Properties: DeviceProperties{SerialNumber: "udid"}}, "test.service", factory)
				result <- err
			}()

			select {
			case <-stageStarted:
			case <-time.After(time.Second):
				t.Fatalf("did not reach blocked %s stage", stage)
			}
			cancel()

			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("ConnectToServiceContext error = %v, want context.Canceled", err)
				}
			case <-time.After(time.Second):
				t.Fatalf("blocked %s stage did not return after cancellation", stage)
			}

			mu.Lock()
			connections := append([]*contextStageDeviceConnection(nil), opened...)
			mu.Unlock()
			for i, conn := range connections {
				select {
				case <-conn.closed:
				case <-time.After(time.Second):
					t.Fatalf("connection %d was not closed", i)
				}
			}
		})
	}
}

func TestConnectToServiceContextDetachesSetupContextAfterSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	firstScript, _ := firstContextStageScript("")
	first := newContextStageDeviceConnection(firstScript, false)
	second := newContextStageDeviceConnection(muxContextTestFrame(MuxResponse{MessageType: "Result"}), false)
	connections := []*contextStageDeviceConnection{first, second}
	call := 0
	factory := func(context.Context) (*UsbMuxConnection, error) {
		conn := connections[call]
		call++
		return NewUsbMuxConnection(conn), nil
	}

	conn, err := connectToServiceContext(ctx, DeviceEntry{DeviceID: 7, Properties: DeviceProperties{SerialNumber: "udid"}}, "test.service", factory)
	if err != nil {
		t.Fatalf("ConnectToServiceContext failed: %v", err)
	}
	cancel()
	select {
	case <-second.closed:
		t.Fatal("successful service connection remained tied to setup context")
	case <-time.After(25 * time.Millisecond):
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close returned %v", err)
	}
}

func TestConnectToServiceContextCancellationClosesRawSocketAtSSLInstallBoundary(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	firstScript, _ := firstContextStageScript(blockSessionSSL)
	first := newSSLSwapBoundaryDeviceConnection(firstScript)
	factory := func(context.Context) (*UsbMuxConnection, error) {
		return NewUsbMuxConnection(first), nil
	}

	result := make(chan error, 1)
	go func() {
		_, err := connectToServiceContext(ctx, DeviceEntry{DeviceID: 7, Properties: DeviceProperties{SerialNumber: "udid"}}, "test.service", factory)
		result <- err
	}()
	select {
	case <-first.sslStarted:
	case <-time.After(time.Second):
		t.Fatal("did not reach SSL installation boundary")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("ConnectToServiceContext error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SSL installation did not unblock after raw socket cancellation")
	}
	if first.closeDuringSwap.Load() {
		t.Fatal("context watcher called DeviceConnection.Close while SSL was replacing its connection")
	}
}

func TestNewDeviceConnectionContextPassesCancellationToDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		_, err := newDeviceConnectionContext(ctx, "tcp://unused:1", func(dialCtx context.Context, network, address string) (net.Conn, error) {
			close(started)
			<-dialCtx.Done()
			return nil, dialCtx.Err()
		})
		result <- err
	}()
	<-started
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("dial error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("socket dial did not return after context cancellation")
	}
}
