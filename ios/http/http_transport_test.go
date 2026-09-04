package http

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

const clientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

type observedConn struct {
	net.Conn

	mu               sync.Mutex
	prefaceRemaining int
	maxPrefaceChunk  int
	prefaceWrites    int
	deadlines        []time.Time
	closeCalls       atomic.Int32
}

func (c *observedConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.prefaceRemaining > 0 {
		limit := len(p)
		if limit > c.maxPrefaceChunk {
			limit = c.maxPrefaceChunk
		}
		if limit > c.prefaceRemaining {
			limit = c.prefaceRemaining
		}
		n, err := c.Conn.Write(p[:limit])
		c.prefaceRemaining -= n
		c.prefaceWrites++
		return n, err
	}
	return c.Conn.Write(p)
}

func (c *observedConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, deadline)
	c.mu.Unlock()
	return c.Conn.SetDeadline(deadline)
}

func (c *observedConn) Close() error {
	c.closeCalls.Add(1)
	return c.Conn.Close()
}

func (c *observedConn) setupObservations() (int, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var lastDeadline time.Time
	if len(c.deadlines) > 0 {
		lastDeadline = c.deadlines[len(c.deadlines)-1]
	}
	return c.prefaceWrites, lastDeadline
}

type peerHandshakeResult struct {
	framer *http2.Framer
	err    error
}

func startHandshakePeer(conn net.Conn) <-chan peerHandshakeResult {
	return startHandshakePeerWithSettings(conn, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1048576})
}

func startHandshakePeerWithSettings(conn net.Conn, settings ...http2.Setting) <-chan peerHandshakeResult {
	result := make(chan peerHandshakeResult, 1)
	go func() {
		preface := make([]byte, len(clientPreface))
		if _, err := io.ReadFull(conn, preface); err != nil {
			result <- peerHandshakeResult{err: err}
			return
		}
		if string(preface) != clientPreface {
			result <- peerHandshakeResult{err: errors.New("invalid client preface")}
			return
		}

		framer := http2.NewFramer(conn, conn)
		frame, err := framer.ReadFrame()
		if err != nil {
			result <- peerHandshakeResult{err: err}
			return
		}
		if frame.Header().Type != http2.FrameSettings {
			result <- peerHandshakeResult{err: errors.New("first client frame was not SETTINGS")}
			return
		}
		frame, err = framer.ReadFrame()
		if err != nil {
			result <- peerHandshakeResult{err: err}
			return
		}
		if frame.Header().Type != http2.FrameWindowUpdate {
			result <- peerHandshakeResult{err: errors.New("second client frame was not WINDOW_UPDATE")}
			return
		}
		if err := framer.WriteSettings(settings...); err != nil {
			result <- peerHandshakeResult{err: err}
			return
		}
		frame, err = framer.ReadFrame()
		if err != nil {
			result <- peerHandshakeResult{err: err}
			return
		}
		settings, ok := frame.(*http2.SettingsFrame)
		if !ok || !settings.IsAck() {
			result <- peerHandshakeResult{err: errors.New("client did not acknowledge peer SETTINGS")}
			return
		}
		result <- peerHandshakeResult{framer: framer}
	}()
	return result
}

func TestNewHttpConnectionAcceptsZeroInitialStreamWindow(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	peerResult := startHandshakePeerWithSettings(server, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection, err := NewHttpConnectionContext(ctx, client)
	if err != nil {
		t.Fatalf("NewHttpConnectionContext() error = %v", err)
	}
	defer connection.Close()
	if peer := <-peerResult; peer.err != nil {
		t.Fatalf("peer handshake error = %v", peer.err)
	}
	connection.flowStateMu.Lock()
	streamWindow := connection.streamSendWindows[uint32(ClientServer)]
	maxFrameSize := connection.maxWriteFrameSize
	connection.flowStateMu.Unlock()
	if streamWindow != 0 {
		t.Fatalf("peer initial stream window = %d, want 0", streamWindow)
	}
	if maxFrameSize != defaultMaxWriteFrameSize {
		t.Fatalf("max DATA frame size = %d, want %d", maxFrameSize, defaultMaxWriteFrameSize)
	}
}

func TestNewHttpConnectionWritesFullPrefaceAndClearsSetupDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	observed := &observedConn{
		Conn:             client,
		prefaceRemaining: len(clientPreface),
		maxPrefaceChunk:  3,
	}
	peerResult := startHandshakePeer(server)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	connection, err := NewHttpConnectionContext(ctx, observed)
	if err != nil {
		cancel()
		t.Fatalf("NewHttpConnectionContext() error = %v", err)
	}
	peer := <-peerResult
	if peer.err != nil {
		cancel()
		_ = connection.Close()
		t.Fatalf("peer handshake error = %v", peer.err)
	}
	prefaceWrites, lastDeadline := observed.setupObservations()
	if prefaceWrites <= 1 {
		t.Fatalf("preface writes = %d, want multiple short writes", prefaceWrites)
	}
	if !lastDeadline.IsZero() {
		t.Fatalf("last transport deadline = %v, want cleared deadline", lastDeadline)
	}
	connection.flowStateMu.Lock()
	streamWindow := connection.streamSendWindows[uint32(ClientServer)]
	maxFrameSize := connection.maxWriteFrameSize
	connection.flowStateMu.Unlock()
	if streamWindow != 1048576 {
		t.Fatalf("peer initial stream window = %d, want 1048576", streamWindow)
	}
	if maxFrameSize != defaultMaxWriteFrameSize {
		t.Fatalf("max DATA frame size = %d, want default %d; INITIAL_WINDOW_SIZE must not set frame size", maxFrameSize, defaultMaxWriteFrameSize)
	}

	// The setup context must no longer own the established connection.
	cancel()
	want := []byte("still-alive")
	writeDone := make(chan error, 1)
	go func() {
		if err := peer.framer.WriteData(uint32(ClientServer), false, want); err != nil {
			writeDone <- err
			return
		}
		for i := 0; i < 2; i++ {
			frame, err := peer.framer.ReadFrame()
			if err != nil {
				writeDone <- err
				return
			}
			if frame.Header().Type != http2.FrameWindowUpdate {
				writeDone <- errors.New("expected flow-control WINDOW_UPDATE")
				return
			}
		}
		writeDone <- nil
	}()
	got := make([]byte, len(want))
	if _, err := connection.ReadClientServerStream(got); err != nil {
		t.Fatalf("ReadClientServerStream() after setup context cancellation error = %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("peer WriteData() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("read payload = %q, want %q", got, want)
	}

	if err := connection.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if got := observed.closeCalls.Load(); got != 1 {
		t.Fatalf("underlying Close calls = %d, want 1", got)
	}
}

func TestNewHttpConnectionContextTimesOutWaitingForPeerSettings(t *testing.T) {
	client, server := net.Pipe()
	observed := &observedConn{Conn: client, maxPrefaceChunk: len(clientPreface)}
	peerReady := make(chan struct{})
	peerClosed := make(chan error, 1)
	go func() {
		defer server.Close()
		preface := make([]byte, len(clientPreface))
		if _, err := io.ReadFull(server, preface); err != nil {
			peerClosed <- err
			return
		}
		framer := http2.NewFramer(server, server)
		if _, err := framer.ReadFrame(); err != nil {
			peerClosed <- err
			return
		}
		if _, err := framer.ReadFrame(); err != nil {
			peerClosed <- err
			return
		}
		close(peerReady)
		oneByte := make([]byte, 1)
		_, err := server.Read(oneByte)
		peerClosed <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := NewHttpConnectionContext(ctx, observed)
		result <- err
	}()
	select {
	case <-peerReady:
	case err := <-peerClosed:
		t.Fatalf("peer failed before becoming silent: %v", err)
	case <-time.After(time.Second):
		t.Fatal("peer did not receive client setup frames")
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("NewHttpConnectionContext() error = %v, want %v", err, context.DeadlineExceeded)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("NewHttpConnectionContext did not stop for a silent peer")
	}
	if got := observed.closeCalls.Load(); got != 1 {
		t.Fatalf("underlying Close calls = %d, want 1", got)
	}
	select {
	case err := <-peerClosed:
		if err == nil {
			t.Fatal("peer read unexpectedly succeeded after client setup timeout")
		}
	case <-time.After(time.Second):
		t.Fatal("peer transport was not closed after setup timeout")
	}
}

func TestNewHttpConnectionRejectsNonSettingsInitialFrame(t *testing.T) {
	client, server := net.Pipe()
	observed := &observedConn{Conn: client, maxPrefaceChunk: len(clientPreface)}
	peerDone := make(chan error, 1)
	go func() {
		defer server.Close()
		preface := make([]byte, len(clientPreface))
		if _, err := io.ReadFull(server, preface); err != nil {
			peerDone <- err
			return
		}
		framer := http2.NewFramer(server, server)
		if _, err := framer.ReadFrame(); err != nil {
			peerDone <- err
			return
		}
		if _, err := framer.ReadFrame(); err != nil {
			peerDone <- err
			return
		}
		if err := framer.WritePing(false, [8]byte{1}); err != nil {
			peerDone <- err
			return
		}
		_, err := framer.ReadFrame()
		peerDone <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection, err := NewHttpConnectionContext(ctx, observed)
	if connection != nil {
		_ = connection.Close()
		t.Fatalf("NewHttpConnectionContext() connection = %v, want nil", connection)
	}
	if err == nil || !strings.Contains(err.Error(), "expected initial peer SETTINGS") {
		t.Fatalf("NewHttpConnectionContext() error = %v, want initial SETTINGS error", err)
	}
	if got := observed.closeCalls.Load(); got != 1 {
		t.Fatalf("underlying Close calls = %d, want 1", got)
	}
	select {
	case err := <-peerDone:
		if err == nil {
			t.Fatal("peer unexpectedly read another frame after protocol error")
		}
	case <-time.After(time.Second):
		t.Fatal("peer was not disconnected after invalid initial frame")
	}
}

type signalingReader struct {
	io.Reader
	once    sync.Once
	started chan struct{}
}

func (r *signalingReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	return r.Reader.Read(p)
}

type pipeReadCloser struct {
	reader *io.PipeReader
}

func (c pipeReadCloser) Close() error {
	return c.reader.Close()
}

type countingPipeReadCloser struct {
	reader *io.PipeReader
	calls  atomic.Int32
}

func (c *countingPipeReadCloser) Close() error {
	c.calls.Add(1)
	return c.reader.Close()
}

func TestConcurrentStreamReadsDoNotBlockBufferedOtherStream(t *testing.T) {
	reader, writer := io.Pipe()
	defer writer.Close()
	signaling := &signalingReader{Reader: reader, started: make(chan struct{})}
	connection := newHTTPConnection(http2.NewFramer(io.Discard, signaling), pipeReadCloser{reader: reader})
	defer connection.Close()
	peer := http2.NewFramer(writer, nil)

	clientResult := make(chan []byte, 1)
	clientErr := make(chan error, 1)
	go func() {
		buf := make([]byte, len("client"))
		_, err := connection.ReadClientServerStream(buf)
		clientResult <- buf
		clientErr <- err
	}()
	select {
	case <-signaling.started:
	case <-time.After(time.Second):
		t.Fatal("client-server reader did not start reading a frame")
	}

	serverResult := make(chan []byte, 1)
	serverErr := make(chan error, 1)
	go func() {
		buf := make([]byte, len("server"))
		_, err := connection.ReadServerClientStream(buf)
		serverResult <- buf
		serverErr <- err
	}()

	if err := peer.WriteData(uint32(ServerClient), false, []byte("server")); err != nil {
		t.Fatalf("write server-client frame: %v", err)
	}
	select {
	case got := <-serverResult:
		if err := <-serverErr; err != nil {
			t.Fatalf("ReadServerClientStream() error = %v", err)
		}
		if string(got) != "server" {
			t.Fatalf("server-client payload = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("server-client reader was blocked by the other stream's pending ReadFrame")
	}

	if err := peer.WriteData(uint32(ClientServer), false, []byte("client")); err != nil {
		t.Fatalf("write client-server frame: %v", err)
	}
	select {
	case got := <-clientResult:
		if err := <-clientErr; err != nil {
			t.Fatalf("ReadClientServerStream() error = %v", err)
		}
		if string(got) != "client" {
			t.Fatalf("client-server payload = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("client-server reader did not receive its frame")
	}
}

type coordinatedControlWriter struct {
	mu sync.Mutex

	output           bytes.Buffer
	dataFrames       int
	windowUpdates    int
	firstDataStarted chan struct{}
	releaseFirstData chan struct{}
	controlWritten   chan struct{}
	controlOnce      sync.Once
}

func newCoordinatedControlWriter() *coordinatedControlWriter {
	return &coordinatedControlWriter{
		firstDataStarted: make(chan struct{}),
		releaseFirstData: make(chan struct{}),
		controlWritten:   make(chan struct{}),
	}
}

func (w *coordinatedControlWriter) Write(p []byte) (int, error) {
	if len(p) < 9 {
		return 0, io.ErrShortWrite
	}
	frameType := http2.FrameType(p[3])
	if frameType == http2.FrameData {
		w.mu.Lock()
		w.dataFrames++
		dataFrameNumber := w.dataFrames
		w.mu.Unlock()
		if dataFrameNumber == 1 {
			close(w.firstDataStarted)
			<-w.releaseFirstData
		} else {
			select {
			case <-w.controlWritten:
			case <-time.After(time.Second):
				return 0, errors.New("application DATA overtook pending control frames")
			}
		}
	}
	if frameType == http2.FrameWindowUpdate {
		w.mu.Lock()
		w.windowUpdates++
		windowUpdates := w.windowUpdates
		w.mu.Unlock()
		if windowUpdates == 2 {
			w.controlOnce.Do(func() { close(w.controlWritten) })
		}
	}
	w.mu.Lock()
	n, err := w.output.Write(p)
	w.mu.Unlock()
	return n, err
}

func TestFlowControlWritesAreNotStarvedByLargeApplicationWrite(t *testing.T) {
	inboundReader, inboundWriter := io.Pipe()
	defer inboundWriter.Close()
	outbound := newCoordinatedControlWriter()
	connection := newHTTPConnection(http2.NewFramer(outbound, inboundReader), pipeReadCloser{reader: inboundReader})
	connection.maxWriteFrameSize = 4
	defer connection.Close()

	applicationWriteDone := make(chan error, 1)
	go func() {
		_, err := connection.WriteClientServerStream([]byte("abcdefghijkl"))
		applicationWriteDone <- err
	}()
	select {
	case <-outbound.firstDataStarted:
	case <-time.After(time.Second):
		t.Fatal("application writer did not reach its first DATA frame")
	}

	readDone := make(chan error, 1)
	go func() {
		_, err := connection.ReadServerClientStream(make([]byte, 1))
		readDone <- err
	}()
	peer := http2.NewFramer(inboundWriter, nil)
	if err := peer.WriteData(uint32(ServerClient), false, []byte("x")); err != nil {
		t.Fatalf("peer WriteData() error = %v", err)
	}
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatalf("ReadServerClientStream() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reader blocked while the peer was not reading flow-control writes")
	}
	close(outbound.releaseFirstData)

	select {
	case <-outbound.controlWritten:
	case err := <-applicationWriteDone:
		if err != nil {
			t.Fatalf("application write failed before control frames: %v", err)
		}
		t.Fatal("application write completed before pending control frames")
	case <-time.After(2 * time.Second):
		t.Fatal("pending flow-control writes were starved by application DATA")
	}
	select {
	case err := <-applicationWriteDone:
		if err != nil {
			t.Fatalf("WriteClientServerStream() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("application writer did not resume after control frames")
	}
}

type dataFrameRecordingWriter struct {
	mu        sync.Mutex
	output    bytes.Buffer
	firstData chan struct{}
	once      sync.Once
}

func (w *dataFrameRecordingWriter) Write(p []byte) (int, error) {
	if len(p) >= 9 && http2.FrameType(p[3]) == http2.FrameData {
		w.once.Do(func() { close(w.firstData) })
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.output.Write(p)
}

func (w *dataFrameRecordingWriter) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.output.Bytes()...)
}

func TestApplicationWriteWaitsForConnectionAndStreamWindowUpdates(t *testing.T) {
	inboundReader, inboundWriter := io.Pipe()
	defer inboundWriter.Close()
	outbound := &dataFrameRecordingWriter{firstData: make(chan struct{})}
	connection := newHTTPConnection(http2.NewFramer(outbound, inboundReader), pipeReadCloser{reader: inboundReader})
	connection.flowStateMu.Lock()
	connection.maxWriteFrameSize = 4
	connection.connectionSendWindow = 4
	connection.streamSendWindows[uint32(ClientServer)] = 4
	connection.flowStateMu.Unlock()
	connection.startReadPump()
	defer connection.Close()

	writeDone := make(chan error, 1)
	go func() {
		_, err := connection.WriteClientServerStream([]byte("abcdefgh"))
		writeDone <- err
	}()
	select {
	case <-outbound.firstData:
	case <-time.After(time.Second):
		t.Fatal("writer did not consume the initial flow-control window")
	}
	select {
	case err := <-writeDone:
		t.Fatalf("write completed without WINDOW_UPDATE: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	peer := http2.NewFramer(inboundWriter, nil)
	if err := peer.WriteWindowUpdate(uint32(InitStream), 4); err != nil {
		t.Fatalf("write connection WINDOW_UPDATE: %v", err)
	}
	select {
	case err := <-writeDone:
		t.Fatalf("write completed without stream WINDOW_UPDATE: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := peer.WriteWindowUpdate(uint32(ClientServer), 4); err != nil {
		t.Fatalf("write stream WINDOW_UPDATE: %v", err)
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("WriteClientServerStream() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("write did not resume after both WINDOW_UPDATE frames")
	}

	decoder := http2.NewFramer(io.Discard, bytes.NewReader(outbound.Bytes()))
	dataFrames := 0
	for {
		frame, err := decoder.ReadFrame()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("decode output: %v", err)
		}
		if data, ok := frame.(*http2.DataFrame); ok {
			dataFrames++
			if len(data.Data()) != 4 {
				t.Fatalf("DATA frame length = %d, want 4", len(data.Data()))
			}
		}
	}
	if dataFrames != 2 {
		t.Fatalf("DATA frames = %d, want 2", dataFrames)
	}
}

func TestUnconsumedStreamBufferLimitIsTerminal(t *testing.T) {
	reader, writer := io.Pipe()
	defer writer.Close()
	signaling := &signalingReader{Reader: reader, started: make(chan struct{})}
	closer := &countingPipeReadCloser{reader: reader}
	connection := newHTTPConnection(http2.NewFramer(io.Discard, signaling), closer)
	connection.maxBufferedStreamBytes = 8
	peer := http2.NewFramer(writer, nil)

	readDone := make(chan error, 1)
	go func() {
		_, err := connection.ReadClientServerStream(make([]byte, 1))
		readDone <- err
	}()
	select {
	case <-signaling.started:
	case <-time.After(time.Second):
		t.Fatal("reader did not start reading a frame")
	}
	if err := peer.WriteData(uint32(ServerClient), false, []byte("123456789")); err != nil {
		t.Fatalf("peer WriteData() error = %v", err)
	}
	select {
	case err := <-readDone:
		if err == nil || !strings.Contains(err.Error(), "exceed limit 8") {
			t.Fatalf("ReadClientServerStream() error = %v, want buffer limit error", err)
		}
	case <-time.After(time.Second):
		t.Fatal("buffer overflow did not terminate the connection")
	}
	if got := closer.calls.Load(); got != 1 {
		t.Fatalf("underlying Close calls = %d, want 1", got)
	}
}

type yieldingWriter struct {
	mu   sync.Mutex
	data []byte
}

func (w *yieldingWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		w.mu.Lock()
		w.data = append(w.data, b)
		w.mu.Unlock()
		runtime.Gosched()
	}
	return len(p), nil
}

func (w *yieldingWriter) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.data...)
}

type httpCountingCloser struct {
	calls atomic.Int32
	err   error
}

func (c *httpCountingCloser) Close() error {
	c.calls.Add(1)
	return c.err
}

func TestHttpConnectionConcurrentCloseIsIdempotent(t *testing.T) {
	wantErr := errors.New("close sentinel")
	closer := &httpCountingCloser{err: wantErr}
	connection := newHTTPConnection(http2.NewFramer(io.Discard, bytes.NewReader(nil)), closer)

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
	select {
	case <-connection.writerDone:
	case <-time.After(time.Second):
		t.Fatal("Close did not stop the idle writer pump")
	}
	if _, err := connection.WriteClientServerStream([]byte("after close")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("WriteClientServerStream() after Close error = %v, want %v", err, io.ErrClosedPipe)
	}
}

func TestHttpConnectionCloseUnblocksFrameRead(t *testing.T) {
	reader, writer := io.Pipe()
	defer writer.Close()
	signaling := &signalingReader{Reader: reader, started: make(chan struct{})}
	connection := newHTTPConnection(http2.NewFramer(io.Discard, signaling), pipeReadCloser{reader: reader})

	readDone := make(chan error, 1)
	go func() {
		_, err := connection.ReadClientServerStream(make([]byte, 1))
		readDone <- err
	}()
	select {
	case <-signaling.started:
	case <-time.After(time.Second):
		t.Fatal("reader did not block in ReadFrame")
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case err := <-readDone:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("ReadClientServerStream() error = %v, want %v", err, io.ErrClosedPipe)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock ReadFrame")
	}
}

func TestLargeStreamWriteIsSplitIntoBoundedDataFrames(t *testing.T) {
	output := &yieldingWriter{}
	connection := newHTTPConnection(http2.NewFramer(output, bytes.NewReader(nil)), nil)
	connection.maxWriteFrameSize = 8
	payload := []byte("0123456789abcdefghijkl")
	if n, err := connection.WriteClientServerStream(payload); err != nil || n != len(payload) {
		t.Fatalf("WriteClientServerStream() = (%d, %v), want (%d, nil)", n, err, len(payload))
	}

	decoder := http2.NewFramer(io.Discard, bytes.NewReader(output.Bytes()))
	frame, err := decoder.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if frame.Header().Type != http2.FrameHeaders {
		t.Fatalf("first frame = %s, want HEADERS", frame.Header().Type)
	}
	var reconstructed []byte
	dataFrames := 0
	for {
		frame, err := decoder.ReadFrame()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, ok := frame.(*http2.DataFrame)
		if !ok {
			t.Fatalf("frame = %T, want DATA", frame)
		}
		if len(data.Data()) > connection.maxWriteFrameSize {
			t.Fatalf("DATA frame length = %d, limit %d", len(data.Data()), connection.maxWriteFrameSize)
		}
		reconstructed = append(reconstructed, data.Data()...)
		dataFrames++
	}
	if dataFrames < 2 {
		t.Fatalf("DATA frames = %d, want a split write", dataFrames)
	}
	if !bytes.Equal(reconstructed, payload) {
		t.Fatalf("reconstructed payload = %q, want %q", reconstructed, payload)
	}
}

type errorWriter struct {
	err error
}

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

func TestRuntimeFrameWriteErrorClosesConnection(t *testing.T) {
	wantErr := errors.New("frame write sentinel")
	closer := &httpCountingCloser{}
	connection := newHTTPConnection(http2.NewFramer(errorWriter{err: wantErr}, bytes.NewReader(nil)), closer)
	if _, err := connection.WriteClientServerStream([]byte("data")); !errors.Is(err, wantErr) {
		t.Fatalf("WriteClientServerStream() error = %v, want %v", err, wantErr)
	}
	if got := closer.calls.Load(); got != 1 {
		t.Fatalf("underlying Close calls = %d, want 1", got)
	}
	select {
	case <-connection.writerDone:
	case <-time.After(time.Second):
		t.Fatal("terminal frame error did not stop the writer pump")
	}
	if _, err := connection.WriteClientServerStream([]byte("again")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("second WriteClientServerStream() error = %v, want %v", err, io.ErrClosedPipe)
	}
}

type blockingFrameTransport struct {
	started    chan struct{}
	closed     chan struct{}
	startOnce  sync.Once
	closeOnce  sync.Once
	closeCalls atomic.Int32
}

func newBlockingFrameTransport() *blockingFrameTransport {
	return &blockingFrameTransport{
		started: make(chan struct{}),
		closed:  make(chan struct{}),
	}
}

func (t *blockingFrameTransport) Write([]byte) (int, error) {
	t.startOnce.Do(func() { close(t.started) })
	<-t.closed
	return 0, io.ErrClosedPipe
}

func (t *blockingFrameTransport) Close() error {
	t.closeCalls.Add(1)
	t.closeOnce.Do(func() { close(t.closed) })
	return nil
}

func TestControlWriteQueueOverflowIsBoundedAndTerminal(t *testing.T) {
	transport := newBlockingFrameTransport()
	connection := newHTTPConnection(http2.NewFramer(transport, bytes.NewReader(nil)), transport)
	ping := func() error { return connection.framer.WritePing(true, [8]byte{1}) }
	if err := connection.queueControlFrame(ping); err != nil {
		t.Fatalf("initial queueControlFrame() error = %v", err)
	}
	select {
	case <-transport.started:
	case <-time.After(time.Second):
		t.Fatal("writer pump did not start the first control frame")
	}
	for i := 0; i < controlWriteQueueSize; i++ {
		if err := connection.queueControlFrame(ping); err != nil {
			t.Fatalf("queueControlFrame(%d) error = %v", i, err)
		}
	}
	err := connection.queueControlFrame(ping)
	if err == nil || !strings.Contains(err.Error(), "control write queue exceeded") {
		t.Fatalf("overflow queueControlFrame() error = %v, want bounded-queue error", err)
	}
	if got := transport.closeCalls.Load(); got != 1 {
		t.Fatalf("underlying Close calls = %d, want 1", got)
	}
	select {
	case <-connection.writerDone:
	case <-time.After(time.Second):
		t.Fatal("control queue overflow did not stop the writer pump")
	}
}

func TestConcurrentFrameWritesAreSerialized(t *testing.T) {
	output := &yieldingWriter{}
	connection := newHTTPConnection(http2.NewFramer(output, bytes.NewReader(nil)), nil)

	const writeCount = 100
	start := make(chan struct{})
	errs := make(chan error, writeCount)
	var wg sync.WaitGroup
	for i := 0; i < writeCount; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			payload := make([]byte, 4)
			binary.LittleEndian.PutUint32(payload, uint32(i))
			if i%2 == 0 {
				_, err := connection.WriteClientServerStream(payload)
				errs <- err
				return
			}
			_, err := connection.WriteServerClientStream(payload)
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("stream Write() error = %v", err)
		}
	}

	decoder := http2.NewFramer(io.Discard, bytes.NewReader(output.Bytes()))
	headers := map[uint32]int{}
	seenPayloads := make(map[uint32]bool, writeCount)
	dataFrames := 0
	for {
		frame, err := decoder.ReadFrame()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("decode concurrently written frame %d: %v", dataFrames, err)
		}
		switch frame := frame.(type) {
		case *http2.HeadersFrame:
			headers[frame.StreamID]++
		case *http2.DataFrame:
			if len(frame.Data()) != 4 {
				t.Fatalf("DATA payload length = %d, want 4", len(frame.Data()))
			}
			value := binary.LittleEndian.Uint32(frame.Data())
			if seenPayloads[value] {
				t.Fatalf("duplicate DATA payload %d", value)
			}
			seenPayloads[value] = true
			if wantStream := uint32(ClientServer); value%2 == 1 {
				wantStream = uint32(ServerClient)
				if frame.StreamID != wantStream {
					t.Fatalf("payload %d stream = %d, want %d", value, frame.StreamID, wantStream)
				}
			} else if frame.StreamID != wantStream {
				t.Fatalf("payload %d stream = %d, want %d", value, frame.StreamID, wantStream)
			}
			dataFrames++
		default:
			t.Fatalf("unexpected frame type %T", frame)
		}
	}
	if dataFrames != writeCount {
		t.Fatalf("DATA frames = %d, want %d", dataFrames, writeCount)
	}
	if headers[uint32(ClientServer)] != 1 || headers[uint32(ServerClient)] != 1 {
		t.Fatalf("HEADERS counts = %#v, want one per stream", headers)
	}
}
