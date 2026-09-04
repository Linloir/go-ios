package http

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

type StreamId uint32

const (
	InitStream   = StreamId(0)
	ClientServer = StreamId(1)
	ServerClient = StreamId(3)
)

const defaultHTTPSetupTimeout = 10 * time.Second

// A single RemoteXPC message may span many DATA frames. Bound each direction
// independently so traffic on an unconsumed stream cannot grow memory without
// limit while the caller is reading only the other stream.
const defaultMaxBufferedStreamBytes = 128 << 20

const defaultMaxWriteFrameSize = 16 << 10

const (
	initialHTTP2FlowWindow = int64(65535)
	maxHTTP2FlowWindow     = int64(1<<31 - 1)
	controlWriteQueueSize  = 128
)

type frameWriteRequest struct {
	write func() error
	done  chan error
}

type onceReadWriteCloser struct {
	io.ReadWriteCloser

	closeOnce sync.Once
	closeErr  error
}

func (c *onceReadWriteCloser) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.ReadWriteCloser.Close()
	})
	return c.closeErr
}

// HttpConnection is a wrapper around a http2.Framer that provides a simple interface to read and write http2 streams for iOS17+.
type HttpConnection struct {
	framer             *http2.Framer
	clientServerStream *bytes.Buffer
	serverClientStream *bytes.Buffer
	closer             io.Closer
	deadlineTarget     interface{ SetDeadline(time.Time) error }

	// http2.Framer permits one reader and one writer in parallel. Application
	// writes are kept logically intact, while the single writer pump serializes
	// frames and gives queued control traffic priority between DATA frames.
	frameReadMu        sync.Mutex
	applicationWriteMu sync.Mutex
	writeRequests      chan frameWriteRequest
	controlWrites      chan frameWriteRequest
	writerStop         chan struct{}
	writerDone         chan struct{}

	flowStateMu          sync.Mutex
	flowCond             *sync.Cond
	connectionSendWindow int64
	initialStreamWindow  int64
	streamSendWindows    map[uint32]int64
	maxWriteFrameSize    int

	// readStateMu protects both stream buffers and coordinates the single
	// goroutine currently pulling the next frame. It is deliberately released
	// while ReadFrame blocks, so data already buffered for the other stream can
	// still be consumed.
	readStateMu            sync.Mutex
	readCond               *sync.Cond
	readActive             bool
	readPumpStarted        bool
	readPumpDone           chan struct{}
	readErr                error
	maxBufferedStreamBytes int

	csIsOpen bool
	scIsOpen bool

	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

func (r *HttpConnection) Close() error {
	r.closeOnce.Do(func() {
		r.closed.Store(true)
		close(r.writerStop)

		r.readStateMu.Lock()
		if r.readErr == nil {
			r.readErr = io.ErrClosedPipe
		}
		if r.readCond != nil {
			r.readCond.Broadcast()
		}
		r.readStateMu.Unlock()
		r.flowStateMu.Lock()
		if r.flowCond != nil {
			r.flowCond.Broadcast()
		}
		r.flowStateMu.Unlock()

		// Do not wait for either pump here. Closing the transport is what unblocks
		// a peer that is silent in ReadFrame or a stalled frame write.
		if r.closer != nil {
			r.closeErr = r.closer.Close()
		}
	})
	return r.closeErr
}

// SetDeadline applies a temporary transport deadline when the underlying
// connection supports it. Context cancellation still closes transports that do
// not expose deadlines, so lack of support is intentionally a no-op.
func (r *HttpConnection) SetDeadline(deadline time.Time) error {
	if r.deadlineTarget == nil {
		return nil
	}
	return r.deadlineTarget.SetDeadline(deadline)
}

// NewHttpConnection takes ownership of rw. If HTTP/2 setup fails, rw is
// closed before the error is returned.
func NewHttpConnection(rw io.ReadWriteCloser) (*HttpConnection, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultHTTPSetupTimeout)
	defer cancel()
	return NewHttpConnectionContext(ctx, rw)
}

// NewHttpConnectionContext creates the HTTP/2 transport and waits for the
// peer's initial SETTINGS frame. The supplied context only bounds setup; a
// successful connection is independent of it. NewHttpConnection applies a
// default setup timeout for callers that do not already have a context.
func NewHttpConnectionContext(ctx context.Context, rw io.ReadWriteCloser) (*HttpConnection, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		_ = rw.Close()
		return nil, fmt.Errorf("NewHttpConnection: setup canceled before start: %w", err)
	}

	owned := &onceReadWriteCloser{ReadWriteCloser: rw}
	keepOpen := false
	defer func() {
		if !keepOpen {
			_ = owned.Close()
		}
	}()

	// Closing the transport is the only generic way to interrupt a blocked
	// ReadFrame/Write when rw does not expose deadlines.
	stopSetupWatch := make(chan struct{})
	setupWatchDone := make(chan struct{})
	go func() {
		defer close(setupWatchDone)
		select {
		case <-ctx.Done():
			_ = owned.Close()
		case <-stopSetupWatch:
		}
	}()
	watchStopped := false
	stopWatch := func() {
		if watchStopped {
			return
		}
		close(stopSetupWatch)
		<-setupWatchDone
		watchStopped = true
	}
	defer stopWatch()

	var deadlineTarget interface{ SetDeadline(time.Time) error }
	if d, ok := rw.(interface{ SetDeadline(time.Time) error }); ok {
		deadlineTarget = d
		if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
			if err := d.SetDeadline(deadline); err != nil {
				return nil, httpSetupError(ctx, "could not set setup deadline", err)
			}
		}
	}

	framer := http2.NewFramer(owned, owned)
	connection := newHTTPConnection(framer, owned)
	defer func() {
		if !keepOpen {
			_ = connection.Close()
		}
	}()
	connection.deadlineTarget = deadlineTarget

	if err := writeAll(owned, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		return nil, httpSetupError(ctx, "could not write PRI", err)
	}

	err := connection.writeSettings(
		http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1048576},
	)
	if err != nil {
		return nil, httpSetupError(ctx, "could not write settings", err)
	}

	err = connection.writeWindowUpdate(uint32(InitStream), 983041)
	if err != nil {
		return nil, httpSetupError(ctx, "could not write window update", err)
	}

	frame, err := connection.readFrame()
	if err != nil {
		return nil, httpSetupError(ctx, "could not read peer settings", err)
	}
	settings, ok := frame.(*http2.SettingsFrame)
	if !ok || settings.IsAck() {
		return nil, fmt.Errorf("NewHttpConnection: expected initial peer SETTINGS, got %s", frame.Header().String())
	}
	if err := connection.applyPeerSettingsAndAck(settings); err != nil {
		return nil, httpSetupError(ctx, "could not write settings ack", err)
	}

	// Stop and join the cancellation watcher before transferring ownership to
	// the returned connection. This prevents a setup context expiring just after
	// success from closing a live transport.
	stopWatch()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("NewHttpConnection: setup did not complete before context ended: %w", err)
	}
	if deadlineTarget != nil {
		if err := deadlineTarget.SetDeadline(time.Time{}); err != nil {
			return nil, fmt.Errorf("NewHttpConnection: could not clear setup deadline: %w", err)
		}
	}
	connection.startReadPump()
	keepOpen = true
	return connection, nil
}

func newHTTPConnection(framer *http2.Framer, closer io.Closer) *HttpConnection {
	connection := &HttpConnection{
		framer:                 framer,
		clientServerStream:     bytes.NewBuffer(nil),
		serverClientStream:     bytes.NewBuffer(nil),
		closer:                 closer,
		maxBufferedStreamBytes: defaultMaxBufferedStreamBytes,
		writeRequests:          make(chan frameWriteRequest),
		controlWrites:          make(chan frameWriteRequest, controlWriteQueueSize),
		writerStop:             make(chan struct{}),
		writerDone:             make(chan struct{}),
		connectionSendWindow:   initialHTTP2FlowWindow,
		initialStreamWindow:    initialHTTP2FlowWindow,
		streamSendWindows: map[uint32]int64{
			uint32(ClientServer): initialHTTP2FlowWindow,
			uint32(ServerClient): initialHTTP2FlowWindow,
		},
		maxWriteFrameSize: defaultMaxWriteFrameSize,
		readPumpDone:      make(chan struct{}),
	}
	connection.readCond = sync.NewCond(&connection.readStateMu)
	connection.flowCond = sync.NewCond(&connection.flowStateMu)
	go connection.runWriter()
	return connection
}

func httpSetupError(ctx context.Context, stage string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("NewHttpConnection: %s: %w", stage, ctxErr)
	}
	// A transport deadline and the context timer may become ready in either
	// order. Preserve the context contract when the I/O deadline we installed
	// fires just before ctx.Err() becomes observable.
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return fmt.Errorf("NewHttpConnection: %s: %w", stage, context.DeadlineExceeded)
	}
	return fmt.Errorf("NewHttpConnection: %s: %w", stage, err)
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n < 0 || n > len(p) {
			return fmt.Errorf("invalid write count %d for %d bytes", n, len(p))
		}
		p = p[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (r *HttpConnection) ReadClientServerStream(p []byte) (int, error) {
	n, err := r.readStream(p, uint32(ClientServer))
	if err != nil {
		return n, fmt.Errorf("ReadClientServerStream: %w", err)
	}
	return n, nil
}

func (r *HttpConnection) WriteClientServerStream(p []byte) (int, error) {
	return r.write(p, uint32(ClientServer))
}

func (r *HttpConnection) WriteServerClientStream(p []byte) (int, error) {
	return r.write(p, uint32(ServerClient))
}

func (r *HttpConnection) write(p []byte, stream uint32) (int, error) {
	// Serialize complete application writes so messages on the same HTTP/2
	// stream cannot interleave. The writer pump still schedules queued control
	// traffic between each bounded DATA frame.
	r.applicationWriteMu.Lock()
	defer r.applicationWriteMu.Unlock()

	var isOpen *bool
	switch stream {
	case uint32(ClientServer):
		isOpen = &r.csIsOpen
	case uint32(ServerClient):
		isOpen = &r.scIsOpen
	default:
		return 0, fmt.Errorf("write: unknown stream id %d", stream)
	}
	err := r.writeFrame(func() error {
		if !*isOpen {
			if err := r.framer.WriteHeaders(http2.HeadersFrameParam{
				StreamID:   stream,
				EndHeaders: true,
			}); err != nil {
				return fmt.Errorf("could not send headers: %w", err)
			}
			*isOpen = true
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("write: %w", err)
	}
	if err := r.writeDataFrames(stream, p); err != nil {
		return 0, fmt.Errorf("write: could not write data: %w", err)
	}
	return len(p), nil
}

func (r *HttpConnection) Write(p []byte, streamId uint32) (int, error) {
	r.applicationWriteMu.Lock()
	defer r.applicationWriteMu.Unlock()
	err := r.writeDataFrames(streamId, p)
	if err != nil {
		return 0, fmt.Errorf("Write: could not write data: %w", err)
	}
	return len(p), nil
}

func (r *HttpConnection) writeSettings(settings ...http2.Setting) error {
	return r.writeFrame(func() error { return r.framer.WriteSettings(settings...) })
}

func (r *HttpConnection) applyPeerSettingsAndAck(settings *http2.SettingsFrame) error {
	if err := r.applyPeerSettings(settings); err != nil {
		return err
	}
	return r.writeControlFrame(func() error { return r.framer.WriteSettingsAck() })
}

func (r *HttpConnection) writeWindowUpdate(streamID, increment uint32) error {
	return r.writeFrame(func() error { return r.framer.WriteWindowUpdate(streamID, increment) })
}

func (r *HttpConnection) acknowledgeData(streamID, increment uint32) error {
	if increment == 0 {
		return nil
	}
	return r.queueControlFrame(func() error {
		if err := r.framer.WriteWindowUpdate(uint32(InitStream), increment); err != nil {
			return err
		}
		return r.framer.WriteWindowUpdate(streamID, increment)
	})
}

func (r *HttpConnection) acknowledgePing(data [8]byte) error {
	return r.queueControlFrame(func() error { return r.framer.WritePing(true, data) })
}

func (r *HttpConnection) acknowledgeSettings() error {
	return r.queueControlFrame(func() error { return r.framer.WriteSettingsAck() })
}

func (r *HttpConnection) runWriter() {
	defer close(r.writerDone)
	for {
		var request frameWriteRequest
		// Drain control work first whenever it is already queued. The second
		// select still lets an idle pump accept either class of work.
		select {
		case <-r.writerStop:
			return
		case request = <-r.controlWrites:
		default:
			select {
			case <-r.writerStop:
				return
			case request = <-r.controlWrites:
			case request = <-r.writeRequests:
			}
		}

		err := request.write()
		if err != nil {
			r.setTerminalError(fmt.Errorf("HTTP/2 frame write failed: %w", err))
			_ = r.Close()
		}
		if request.done != nil {
			request.done <- err
		}
		if err != nil {
			return
		}
	}
}

func (r *HttpConnection) writeFrame(write func() error) error {
	return r.submitFrame(frameWriteRequest{write: write, done: make(chan error, 1)}, r.writeRequests)
}

func (r *HttpConnection) writeControlFrame(write func() error) error {
	return r.submitFrame(frameWriteRequest{write: write, done: make(chan error, 1)}, r.controlWrites)
}

func (r *HttpConnection) submitFrame(request frameWriteRequest, queue chan<- frameWriteRequest) error {
	if r.closed.Load() {
		return io.ErrClosedPipe
	}
	select {
	case queue <- request:
	case <-r.writerStop:
		return io.ErrClosedPipe
	}
	select {
	case err := <-request.done:
		return err
	case <-r.writerDone:
		select {
		case err := <-request.done:
			return err
		default:
			return io.ErrClosedPipe
		}
	}
}

func (r *HttpConnection) queueControlFrame(write func() error) error {
	if r.closed.Load() {
		return io.ErrClosedPipe
	}
	request := frameWriteRequest{write: write}
	select {
	case r.controlWrites <- request:
		return nil
	case <-r.writerStop:
		return io.ErrClosedPipe
	default:
		err := fmt.Errorf("HTTP/2 control write queue exceeded %d frames", controlWriteQueueSize)
		r.setTerminalError(err)
		_ = r.Close()
		return err
	}
}

func (r *HttpConnection) writeDataFrames(streamID uint32, p []byte) error {
	if len(p) == 0 {
		return r.writeFrame(func() error {
			return r.framer.WriteData(streamID, false, nil)
		})
	}
	for len(p) > 0 {
		written, err := r.reserveSendWindow(streamID, len(p))
		if err != nil {
			return err
		}
		chunk := p[:written]
		if err := r.writeFrame(func() error {
			return r.framer.WriteData(streamID, false, chunk)
		}); err != nil {
			return err
		}
		p = p[written:]
	}
	return nil
}

func (r *HttpConnection) reserveSendWindow(streamID uint32, requested int) (int, error) {
	r.flowStateMu.Lock()
	defer r.flowStateMu.Unlock()
	for {
		if r.closed.Load() {
			return 0, io.ErrClosedPipe
		}
		streamWindow, ok := r.streamSendWindows[streamID]
		if !ok {
			streamWindow = r.initialStreamWindow
			r.streamSendWindows[streamID] = streamWindow
		}
		allowed := int64(requested)
		if maxFrame := int64(r.maxWriteFrameSize); maxFrame > 0 && allowed > maxFrame {
			allowed = maxFrame
		}
		if allowed > r.connectionSendWindow {
			allowed = r.connectionSendWindow
		}
		if allowed > streamWindow {
			allowed = streamWindow
		}
		if allowed > 0 {
			r.connectionSendWindow -= allowed
			r.streamSendWindows[streamID] = streamWindow - allowed
			return int(allowed), nil
		}
		r.flowCond.Wait()
	}
}

func (r *HttpConnection) applyPeerSettings(settings *http2.SettingsFrame) error {
	if settings.HasDuplicates() {
		return errors.New("peer SETTINGS contains duplicate identifiers")
	}
	var initialWindow *uint32
	var maxFrameSize *uint32
	if err := settings.ForeachSetting(func(setting http2.Setting) error {
		if err := setting.Valid(); err != nil {
			return err
		}
		switch setting.ID {
		case http2.SettingInitialWindowSize:
			value := setting.Val
			initialWindow = &value
		case http2.SettingMaxFrameSize:
			value := setting.Val
			maxFrameSize = &value
		}
		return nil
	}); err != nil {
		return err
	}

	r.flowStateMu.Lock()
	defer r.flowStateMu.Unlock()
	if initialWindow != nil {
		newInitial := int64(*initialWindow)
		delta := newInitial - r.initialStreamWindow
		updatedWindows := make(map[uint32]int64, len(r.streamSendWindows))
		for streamID, window := range r.streamSendWindows {
			updated := window + delta
			if updated > maxHTTP2FlowWindow {
				return fmt.Errorf("peer initial window update overflows stream %d window", streamID)
			}
			updatedWindows[streamID] = updated
		}
		for streamID, window := range updatedWindows {
			r.streamSendWindows[streamID] = window
		}
		r.initialStreamWindow = newInitial
	}
	if maxFrameSize != nil {
		r.maxWriteFrameSize = int(*maxFrameSize)
	}
	r.flowCond.Broadcast()
	return nil
}

func (r *HttpConnection) applyWindowUpdate(streamID, increment uint32) error {
	if increment == 0 {
		return errors.New("peer WINDOW_UPDATE has zero increment")
	}
	r.flowStateMu.Lock()
	defer r.flowStateMu.Unlock()
	if streamID == uint32(InitStream) {
		if r.connectionSendWindow > maxHTTP2FlowWindow-int64(increment) {
			return errors.New("peer WINDOW_UPDATE overflows connection send window")
		}
		r.connectionSendWindow += int64(increment)
	} else {
		window, ok := r.streamSendWindows[streamID]
		if !ok {
			return fmt.Errorf("peer WINDOW_UPDATE references unknown stream %d", streamID)
		}
		if window > maxHTTP2FlowWindow-int64(increment) {
			return fmt.Errorf("peer WINDOW_UPDATE overflows stream %d send window", streamID)
		}
		r.streamSendWindows[streamID] = window + int64(increment)
	}
	r.flowCond.Broadcast()
	return nil
}

func (r *HttpConnection) readFrame() (http2.Frame, error) {
	r.frameReadMu.Lock()
	defer r.frameReadMu.Unlock()
	return r.framer.ReadFrame()
}

func (r *HttpConnection) startReadPump() {
	r.readStateMu.Lock()
	if r.readPumpStarted || r.closed.Load() {
		r.readStateMu.Unlock()
		return
	}
	r.readPumpStarted = true
	r.readCond.Broadcast()
	r.readStateMu.Unlock()

	go func() {
		defer close(r.readPumpDone)
		for {
			if err := r.readDataFrame(); err != nil {
				r.setTerminalError(err)
				_ = r.Close()
				return
			}
		}
	}()
}

func (r *HttpConnection) setTerminalError(err error) {
	if err == nil || r.closed.Load() {
		return
	}
	r.readStateMu.Lock()
	if r.readErr == nil {
		r.readErr = err
	}
	r.readCond.Broadcast()
	r.readStateMu.Unlock()
	r.flowStateMu.Lock()
	r.flowCond.Broadcast()
	r.flowStateMu.Unlock()
}

func (r *HttpConnection) readDataFrame() error {
	for {
		f, err := r.readFrame()
		if err != nil {
			return fmt.Errorf("readDataFrame: could not read frame. %w", err)
		}
		switch f.Header().Type {
		case http2.FrameData:
			d := f.(*http2.DataFrame)
			r.readStateMu.Lock()
			var stream *bytes.Buffer
			switch d.StreamID {
			case uint32(ClientServer):
				stream = r.clientServerStream
			case uint32(ServerClient):
				stream = r.serverClientStream
			default:
				r.readStateMu.Unlock()
				return fmt.Errorf("readDataFrame: unknown stream id %d", d.StreamID)
			}
			limit := r.maxBufferedStreamBytes
			if limit <= 0 {
				limit = defaultMaxBufferedStreamBytes
			}
			if len(d.Data()) > limit || stream.Len() > limit-len(d.Data()) {
				buffered := stream.Len()
				r.readStateMu.Unlock()
				return fmt.Errorf("readDataFrame: stream %d buffered data would exceed limit %d (%d + %d)", d.StreamID, limit, buffered, len(d.Data()))
			}
			_, err = stream.Write(d.Data())
			if r.readCond != nil {
				r.readCond.Broadcast()
			}
			r.readStateMu.Unlock()
			if err != nil {
				return fmt.Errorf("readDataFrame: buffer stream %d: %w", d.StreamID, err)
			}
			if err := r.acknowledgeData(d.StreamID, d.Header().Length); err != nil {
				return fmt.Errorf("readDataFrame: replenish flow-control window: %w", err)
			}
			return nil
		case http2.FrameGoAway:
			return fmt.Errorf("received GOAWAY")
		case http2.FrameSettings:
			s := f.(*http2.SettingsFrame)
			if s.Flags&http2.FlagSettingsAck != http2.FlagSettingsAck {
				if err := r.applyPeerSettings(s); err != nil {
					return fmt.Errorf("readDataFrame: invalid peer settings: %w", err)
				}
				if err := r.acknowledgeSettings(); err != nil {
					return fmt.Errorf("readDataFrame: could not queue settings ack: %w", err)
				}
			}
		case http2.FrameWindowUpdate:
			windowUpdate := f.(*http2.WindowUpdateFrame)
			if err := r.applyWindowUpdate(windowUpdate.StreamID, windowUpdate.Increment); err != nil {
				return fmt.Errorf("readDataFrame: invalid WINDOW_UPDATE: %w", err)
			}
		case http2.FramePing:
			ping := f.(*http2.PingFrame)
			if ping.Flags&http2.FlagPingAck != http2.FlagPingAck {
				if err := r.acknowledgePing(ping.Data); err != nil {
					return fmt.Errorf("readDataFrame: could not write ping ack: %w", err)
				}
			}
		case http2.FrameRSTStream:
			r := f.(*http2.RSTStreamFrame)
			return fmt.Errorf("readDataFrame: got RST frame with error code: %s", r.ErrCode.String())
		default:
			break
		}
	}
}

func (r *HttpConnection) ReadServerClientStream(p []byte) (int, error) {
	n, err := r.readStream(p, uint32(ServerClient))
	if err != nil {
		return n, fmt.Errorf("ReadServerClientStream: %w", err)
	}
	return n, nil
}

func (r *HttpConnection) readStream(p []byte, streamID uint32) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	r.readStateMu.Lock()
	for {
		stream, err := r.streamBufferLocked(streamID)
		if err != nil {
			r.readStateMu.Unlock()
			return 0, err
		}
		if stream.Len() >= len(p) {
			n, readErr := stream.Read(p)
			r.readStateMu.Unlock()
			return n, readErr
		}
		if r.readErr != nil {
			terminalErr := r.readErr
			if stream.Len() > 0 {
				n, readErr := stream.Read(p)
				r.readStateMu.Unlock()
				return n, readErr
			}
			r.readStateMu.Unlock()
			_ = r.Close()
			return 0, terminalErr
		}
		if r.readPumpStarted {
			r.readCond.Wait()
			continue
		}
		if r.readActive {
			r.readCond.Wait()
			continue
		}

		// Only one reader pulls a frame, but no buffer/state lock is held while
		// it blocks. A concurrent reader for the other stream can therefore
		// consume data that was already dispatched to its buffer.
		r.readActive = true
		r.readStateMu.Unlock()
		frameErr := r.readDataFrame()
		r.readStateMu.Lock()
		r.readActive = false
		if frameErr != nil && r.readErr == nil {
			r.readErr = frameErr
		}
		r.readCond.Broadcast()
		if frameErr != nil {
			// A framing/read error is terminal. Close immediately even when a
			// partial payload remains buffered and the caller never reads again.
			r.readStateMu.Unlock()
			_ = r.Close()
			r.readStateMu.Lock()
		}
	}
}

func (r *HttpConnection) streamBufferLocked(streamID uint32) (*bytes.Buffer, error) {
	switch streamID {
	case uint32(ClientServer):
		return r.clientServerStream, nil
	case uint32(ServerClient):
		return r.serverClientStream, nil
	default:
		return nil, fmt.Errorf("unknown stream id %d", streamID)
	}
}

type HttpStreamReadWriter struct {
	h        *HttpConnection
	streamId uint32
}

func NewStreamReadWriter(h *HttpConnection, streamId StreamId) HttpStreamReadWriter {
	return HttpStreamReadWriter{
		h:        h,
		streamId: uint32(streamId),
	}
}

func (h HttpStreamReadWriter) Read(p []byte) (n int, err error) {
	if h.streamId == 1 {
		return h.h.ReadClientServerStream(p)
	}
	if h.streamId == 3 {
		return h.h.ReadServerClientStream(p)
	}
	return 0, fmt.Errorf("Read: unknown stream id %d", h.streamId)
}

func (h HttpStreamReadWriter) Write(p []byte) (n int, err error) {
	if h.streamId == 1 {
		return h.h.WriteClientServerStream(p)
	}
	if h.streamId == 3 {
		return h.h.WriteServerClientStream(p)
	}
	return 0, fmt.Errorf("Write: unknown stream id %d", h.streamId)
}
