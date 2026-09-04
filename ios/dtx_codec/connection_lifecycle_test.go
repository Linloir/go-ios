package dtx

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielpaulus/go-ios/ios"
)

type eofReadWriteCloser struct {
	closeCalls atomic.Int32
}

func (c *eofReadWriteCloser) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *eofReadWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (c *eofReadWriteCloser) Close() error {
	c.closeCalls.Add(1)
	return nil
}

type blockingReadWriteCloser struct {
	closed     chan struct{}
	closeOnce  sync.Once
	closeCalls atomic.Int32
}

type recordingReadWriteCloser struct {
	closed     chan struct{}
	closeOnce  sync.Once
	closeCalls atomic.Int32
	mu         sync.Mutex
	written    bytes.Buffer
	writeLimit int
	writeErr   error
}

func newRecordingReadWriteCloser(writeLimit int, writeErr error) *recordingReadWriteCloser {
	return &recordingReadWriteCloser{
		closed:     make(chan struct{}),
		writeLimit: writeLimit,
		writeErr:   writeErr,
	}
}

func (c *recordingReadWriteCloser) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.EOF
}

func (c *recordingReadWriteCloser) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	limit := len(p)
	if c.writeLimit > 0 && limit > c.writeLimit {
		limit = c.writeLimit
	}
	n, err := c.written.Write(p[:limit])
	runtime.Gosched()
	return n, err
}

func (c *recordingReadWriteCloser) Close() error {
	c.closeCalls.Add(1)
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *recordingReadWriteCloser) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.written.Bytes()...)
}

func newBlockingReadWriteCloser() *blockingReadWriteCloser {
	return &blockingReadWriteCloser{closed: make(chan struct{})}
}

func (c *blockingReadWriteCloser) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.EOF
}

func (c *blockingReadWriteCloser) Write(p []byte) (int, error) { return len(p), nil }

func (c *blockingReadWriteCloser) Close() error {
	c.closeCalls.Add(1)
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func TestReaderEOFClosesUnderlyingConnectionOnce(t *testing.T) {
	rwc := &eofReadWriteCloser{}
	conn, err := newDtxConnection(ios.NewDeviceConnectionWithRWC(rwc))
	if err != nil {
		t.Fatalf("newDtxConnection() error = %v", err)
	}

	select {
	case <-conn.Closed():
	case <-time.After(time.Second):
		t.Fatal("connection did not close after EOF")
	}
	if !errors.Is(conn.Err(), io.EOF) {
		t.Fatalf("connection error = %v, want EOF", conn.Err())
	}
	deadline := time.Now().Add(time.Second)
	for rwc.closeCalls.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := rwc.closeCalls.Load(); got != 1 {
		t.Fatalf("underlying Close calls after EOF = %d, want 1", got)
	}

	_ = conn.Close()
	if got := rwc.closeCalls.Load(); got != 1 {
		t.Fatalf("underlying Close calls after explicit Close = %d, want 1", got)
	}
}

func TestConnectionCloseIsIdempotent(t *testing.T) {
	rwc := newBlockingReadWriteCloser()
	conn, err := newDtxConnection(ios.NewDeviceConnectionWithRWC(rwc))
	if err != nil {
		t.Fatalf("newDtxConnection() error = %v", err)
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}

	select {
	case <-conn.Closed():
	case <-time.After(time.Second):
		t.Fatal("connection did not report closed")
	}
	if !errors.Is(conn.Err(), ErrConnectionClosed) {
		t.Fatalf("connection error = %v, want ErrConnectionClosed", conn.Err())
	}
	if got := rwc.closeCalls.Load(); got != 1 {
		t.Fatalf("underlying Close calls = %d, want 1", got)
	}
}

func TestConnectionSendCompletesShortWrites(t *testing.T) {
	rwc := newRecordingReadWriteCloser(2, nil)
	conn, err := newDtxConnection(ios.NewDeviceConnectionWithRWC(rwc))
	if err != nil {
		t.Fatalf("newDtxConnection() error = %v", err)
	}
	defer conn.Close()

	want := []byte("complete DTX frame")
	if err := conn.Send(want); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if got := rwc.bytes(); !bytes.Equal(got, want) {
		t.Fatalf("written bytes = %q, want %q", got, want)
	}
}

func TestConnectionSendErrorClosesTransportAndSignalsWaiters(t *testing.T) {
	writeErr := errors.New("write failed")
	rwc := newRecordingReadWriteCloser(0, writeErr)
	conn, err := newDtxConnection(ios.NewDeviceConnectionWithRWC(rwc))
	if err != nil {
		t.Fatalf("newDtxConnection() error = %v", err)
	}

	if err := conn.Send([]byte("frame")); !errors.Is(err, writeErr) {
		t.Fatalf("Send() error = %v, want %v", err, writeErr)
	}
	select {
	case <-conn.Closed():
	case <-time.After(time.Second):
		t.Fatal("connection did not signal Closed after write error")
	}
	if !errors.Is(conn.Err(), writeErr) {
		t.Fatalf("connection error = %v, want %v", conn.Err(), writeErr)
	}
	if got := rwc.closeCalls.Load(); got != 1 {
		t.Fatalf("underlying Close calls = %d, want 1", got)
	}
}

func TestConcurrentConnectionSendsDoNotInterleaveFrames(t *testing.T) {
	rwc := newRecordingReadWriteCloser(1, nil)
	conn, err := newDtxConnection(ios.NewDeviceConnectionWithRWC(rwc))
	if err != nil {
		t.Fatalf("newDtxConnection() error = %v", err)
	}
	defer conn.Close()

	frameA := bytes.Repeat([]byte{'A'}, 64)
	frameB := bytes.Repeat([]byte{'B'}, 64)
	start := make(chan struct{})
	errs := make(chan error, 2)
	for _, frame := range [][]byte{frameA, frameB} {
		frame := frame
		go func() {
			<-start
			errs <- conn.Send(frame)
		}()
	}
	close(start)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("Send() error = %v", err)
		}
	}
	written := rwc.bytes()
	wantAB := append(append([]byte(nil), frameA...), frameB...)
	wantBA := append(append([]byte(nil), frameB...), frameA...)
	if !bytes.Equal(written, wantAB) && !bytes.Equal(written, wantBA) {
		t.Fatalf("concurrent DTX frames interleaved: %q", written)
	}
}

func TestForChannelRequestContextStopsOnCancellation(t *testing.T) {
	rwc := newBlockingReadWriteCloser()
	conn, err := newDtxConnection(ios.NewDeviceConnectionWithRWC(rwc))
	if err != nil {
		t.Fatalf("newDtxConnection() error = %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	channel, err := conn.ForChannelRequestContext(ctx, nil)
	if channel != nil {
		t.Fatalf("channel = %v, want nil", channel)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestForChannelRequestContextStopsWhenConnectionCloses(t *testing.T) {
	rwc := newBlockingReadWriteCloser()
	conn, err := newDtxConnection(ios.NewDeviceConnectionWithRWC(rwc))
	if err != nil {
		t.Fatalf("newDtxConnection() error = %v", err)
	}

	result := make(chan error, 1)
	go func() {
		_, err := conn.ForChannelRequestContext(context.Background(), nil)
		result <- err
	}()

	if err := conn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrConnectionClosed) {
			t.Fatalf("error = %v, want ErrConnectionClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ForChannelRequestContext remained blocked after connection close")
	}
}

func TestDefaultChannelCodeUsesSignedWireValue(t *testing.T) {
	header := make([]byte, DtxMessageHeaderLength)
	binary.LittleEndian.PutUint32(header[24:], ^uint32(0))
	if got := readHeader(header).ChannelCode; got != -1 {
		t.Fatalf("decoded default channel = %d, want -1", got)
	}

	conn := &Connection{}
	channel := conn.AddDefaultChannelReceiver(nil)
	stored, ok := conn.activeChannels.Load(-1)
	if !ok {
		t.Fatal("default channel was not registered under decoded channel code -1")
	}
	if stored != channel {
		t.Fatalf("registered default channel = %v, want %v", stored, channel)
	}
}

func TestCanceledMethodCallRemovesWaiterAndDropsLateResponse(t *testing.T) {
	rwc := newBlockingReadWriteCloser()
	conn, err := newDtxConnection(ios.NewDeviceConnectionWithRWC(rwc))
	if err != nil {
		t.Fatalf("newDtxConnection() error = %v", err)
	}
	defer conn.Close()

	channel := &Channel{
		channelCode:       1,
		channelName:       "lifecycle-test",
		messageIdentifier: 1,
		connection:        conn,
		responseWaiters:   map[int]chan Message{},
		defragmenters:     map[int]*FragmentDecoder{},
		timeout:           time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = channel.sendAndAwaitReply(ctx, true, Methodinvocation, nil, NewPrimitiveDictionary())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("sendAndAwaitReply() error = %v, want context.Canceled", err)
	}
	channel.mutex.Lock()
	waiterCount := len(channel.responseWaiters)
	channel.mutex.Unlock()
	if waiterCount != 0 {
		t.Fatalf("response waiter count = %d, want 0", waiterCount)
	}

	dispatched := make(chan struct{})
	go func() {
		channel.Dispatch(Message{Identifier: 1, ConversationIndex: 1})
		close(dispatched)
	}()
	select {
	case <-dispatched:
	case <-time.After(time.Second):
		t.Fatal("late response blocked the DTX dispatcher")
	}
}

func TestReceiveMethodCallStopsWhenConnectionCloses(t *testing.T) {
	rwc := newBlockingReadWriteCloser()
	conn, err := newDtxConnection(ios.NewDeviceConnectionWithRWC(rwc))
	if err != nil {
		t.Fatalf("newDtxConnection() error = %v", err)
	}

	channel := conn.GlobalChannel()
	channel.RegisterMethodForRemote("event:")
	result := make(chan error, 1)
	go func() {
		_, err := channel.ReceiveMethodCallWithTimeout(context.Background(), "event:")
		result <- err
	}()

	if err := conn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrConnectionClosed) {
			t.Fatalf("ReceiveMethodCallWithTimeout() error = %v, want ErrConnectionClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReceiveMethodCallWithTimeout remained blocked after connection close")
	}
}

func TestRegisteredMethodQueueDoesNotBlockDTXReaderWhenFull(t *testing.T) {
	rwc := newBlockingReadWriteCloser()
	conn, err := newDtxConnection(ios.NewDeviceConnectionWithRWC(rwc))
	if err != nil {
		t.Fatalf("newDtxConnection() error = %v", err)
	}
	defer conn.Close()

	channel := conn.GlobalChannel()
	channel.RegisterMethodForRemote("event:")
	for identifier := 1; identifier <= 9; identifier++ {
		channel.Dispatch(Message{
			Identifier:    identifier,
			PayloadHeader: PayloadHeader{MessageType: Methodinvocation},
			Payload:       []interface{}{"event:"},
		})
	}

	msg, err := channel.ReceiveMethodCallWithTimeout(context.Background(), "event:")
	if err != nil {
		t.Fatalf("ReceiveMethodCallWithTimeout() error = %v", err)
	}
	if msg.Identifier != 2 {
		t.Fatalf("oldest retained identifier = %d, want 2 after bounded drop", msg.Identifier)
	}
}

func TestLateFragmentedResponseDoesNotCreateOrphanDecoder(t *testing.T) {
	rwc := newBlockingReadWriteCloser()
	conn, err := newDtxConnection(ios.NewDeviceConnectionWithRWC(rwc))
	if err != nil {
		t.Fatalf("newDtxConnection() error = %v", err)
	}
	defer conn.Close()

	channel := &Channel{
		channelCode:     1,
		channelName:     "fragment-lifecycle-test",
		connection:      conn,
		responseWaiters: map[int]chan Message{},
		defragmenters:   map[int]*FragmentDecoder{},
	}
	channel.Dispatch(Message{
		Fragments:         2,
		FragmentIndex:     0,
		Identifier:        99,
		ConversationIndex: 1,
	})

	channel.mutex.Lock()
	decoderCount := len(channel.defragmenters)
	channel.mutex.Unlock()
	if decoderCount != 0 {
		t.Fatalf("defragmenter count = %d, want 0", decoderCount)
	}
}

func TestOutOfOrderLastFragmentWaitsForMissingFragments(t *testing.T) {
	rwc := newBlockingReadWriteCloser()
	conn, err := newDtxConnection(ios.NewDeviceConnectionWithRWC(rwc))
	if err != nil {
		t.Fatalf("newDtxConnection() error = %v", err)
	}
	defer conn.Close()

	channel := &Channel{
		channelCode:     1,
		channelName:     "out-of-order-fragment-test",
		connection:      conn,
		responseWaiters: map[int]chan Message{7: make(chan Message, 1)},
		defragmenters:   map[int]*FragmentDecoder{},
	}
	channel.Dispatch(Message{
		Fragments:         3,
		FragmentIndex:     0,
		MessageLength:     16,
		Identifier:        7,
		ConversationIndex: 1,
	})
	channel.Dispatch(Message{
		Fragments:         3,
		FragmentIndex:     2,
		Identifier:        7,
		ConversationIndex: 1,
	})

	channel.mutex.Lock()
	decoder := channel.defragmenters[7]
	channel.mutex.Unlock()
	if decoder == nil || decoder.HasFinished() {
		t.Fatalf("decoder after early last fragment = %#v, want incomplete", decoder)
	}
}

func TestStaleUnsolicitedFragmentAssemblyIsEvicted(t *testing.T) {
	channel := &Channel{
		responseWaiters: map[int]chan Message{},
		defragmenters:   map[int]*FragmentDecoder{},
	}
	first := Message{
		Fragments:         2,
		FragmentIndex:     0,
		MessageLength:     16,
		Identifier:        41,
		ConversationIndex: 0,
	}
	decoder := NewFragmentDecoder(first)
	decoder.lastUpdated = time.Now().Add(-fragmentAssemblyTTL - time.Second)
	channel.defragmenters[first.Identifier] = decoder

	channel.Dispatch(Message{Identifier: 42})

	if got := len(channel.defragmenters); got != 0 {
		t.Fatalf("defragmenter count after stale eviction = %d, want 0", got)
	}
}

func TestUnsolicitedFragmentAssembliesAreBounded(t *testing.T) {
	channel := &Channel{
		responseWaiters: map[int]chan Message{},
		defragmenters:   map[int]*FragmentDecoder{},
	}
	for identifier := 1; identifier <= maxDTXFragmentAssembliesPerChannel+1; identifier++ {
		channel.Dispatch(Message{
			Fragments:         2,
			FragmentIndex:     0,
			MessageLength:     16,
			Identifier:        identifier,
			ConversationIndex: 0,
		})
	}

	if got := len(channel.defragmenters); got != maxDTXFragmentAssembliesPerChannel {
		t.Fatalf("defragmenter count = %d, want %d", got, maxDTXFragmentAssembliesPerChannel)
	}
}

func TestFragmentAssemblyAggregateBytesAreBounded(t *testing.T) {
	channel := &Channel{
		responseWaiters: map[int]chan Message{},
		defragmenters:   map[int]*FragmentDecoder{},
	}
	for identifier := 1; identifier <= 3; identifier++ {
		channel.Dispatch(Message{
			Fragments:         2,
			FragmentIndex:     0,
			MessageLength:     100 << 20,
			Identifier:        identifier,
			ConversationIndex: 0,
		})
	}

	if got := len(channel.defragmenters); got != 2 {
		t.Fatalf("defragmenter count = %d, want 2 within aggregate byte cap", got)
	}
}

func TestDecoderRejectsOversizedPeerAllocation(t *testing.T) {
	header := make([]byte, DtxMessageHeaderLength)
	binary.BigEndian.PutUint32(header, DtxMessageMagic)
	binary.LittleEndian.PutUint32(header[4:], DtxMessageHeaderLength)
	binary.LittleEndian.PutUint16(header[10:], 1)
	binary.LittleEndian.PutUint32(header[12:], maxDTXMessageLength+1)

	if _, _, err := DecodeNonBlocking(header); err == nil {
		t.Fatal("DecodeNonBlocking() error = nil, want oversized message rejection")
	}
	if _, err := ReadMessage(bytes.NewReader(header)); err == nil {
		t.Fatal("ReadMessage() error = nil, want oversized message rejection")
	}
}

func TestDecoderRejectsMalformedHeaderAndShortMessageBeforePayloadRead(t *testing.T) {
	header := make([]byte, DtxMessageHeaderLength)
	binary.BigEndian.PutUint32(header, DtxMessageMagic)
	binary.LittleEndian.PutUint32(header[4:], DtxMessageHeaderLength-1)
	binary.LittleEndian.PutUint16(header[10:], 1)
	binary.LittleEndian.PutUint32(header[12:], DtxMessagePayloadHeaderLength)

	if _, _, err := DecodeNonBlocking(header); err == nil {
		t.Fatal("DecodeNonBlocking() error = nil, want malformed header rejection")
	}
	if _, err := ReadMessage(bytes.NewReader(header)); err == nil {
		t.Fatal("ReadMessage() error = nil, want malformed header rejection")
	}

	binary.LittleEndian.PutUint32(header[4:], DtxMessageHeaderLength)
	binary.LittleEndian.PutUint32(header[12:], DtxMessagePayloadHeaderLength-1)
	if _, _, err := DecodeNonBlocking(header); err == nil {
		t.Fatal("DecodeNonBlocking() error = nil, want short message rejection")
	}
	if _, err := ReadMessage(bytes.NewReader(header)); err == nil {
		t.Fatal("ReadMessage() error = nil, want short message rejection before payload read")
	}
}

func TestDecoderRejectsMalformedFragmentTupleBeforePayloadRead(t *testing.T) {
	tests := []struct {
		name          string
		fragmentIndex uint16
		fragments     uint16
		messageLength uint32
		want          string
	}{
		{name: "zero fragment count", fragments: 0, messageLength: DtxMessagePayloadHeaderLength, want: "at least 1"},
		{name: "unfragmented nonzero index", fragmentIndex: 1, fragments: 1, messageLength: DtxMessagePayloadHeaderLength, want: "fragment index"},
		{name: "index outside fragment count", fragmentIndex: 3, fragments: 3, messageLength: 1, want: "outside fragment count"},
		{name: "fragment count above limit", fragmentIndex: 1, fragments: maxDTXFragmentCount + 1, messageLength: 1, want: "exceeds limit"},
		{name: "fragment payload above assembly limit", fragmentIndex: 1, fragments: 2, messageLength: maxDTXFragmentedMessageSize + 1, want: "fragmented message length"},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			header := make([]byte, DtxMessageHeaderLength)
			binary.BigEndian.PutUint32(header, DtxMessageMagic)
			binary.LittleEndian.PutUint32(header[4:], DtxMessageHeaderLength)
			binary.LittleEndian.PutUint16(header[8:], testCase.fragmentIndex)
			binary.LittleEndian.PutUint16(header[10:], testCase.fragments)
			binary.LittleEndian.PutUint32(header[12:], testCase.messageLength)

			if _, _, err := DecodeNonBlocking(header); err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("DecodeNonBlocking() error = %v, want containing %q", err, testCase.want)
			}
			if _, err := ReadMessage(bytes.NewReader(header)); err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("ReadMessage() error = %v, want containing %q before payload read", err, testCase.want)
			}
		})
	}
}

func TestDecoderRejectsInconsistentPayloadAndAuxiliaryLengths(t *testing.T) {
	tests := []struct {
		name          string
		messageLength uint32
		totalLength   uint32
		auxLength     uint32
		auxSize       uint32
	}{
		{name: "total_mismatch", messageLength: 16, totalLength: 1},
		{name: "auxiliary_underflow", messageLength: 24, totalLength: 8, auxLength: 9},
		{name: "short_auxiliary_header", messageLength: 24, totalLength: 8, auxLength: 1},
		{name: "auxiliary_size_mismatch", messageLength: 32, totalLength: 16, auxLength: 16, auxSize: 1},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			wire := make([]byte, 64)
			binary.BigEndian.PutUint32(wire, DtxMessageMagic)
			binary.LittleEndian.PutUint32(wire[4:], DtxMessageHeaderLength)
			binary.LittleEndian.PutUint16(wire[10:], 1)
			binary.LittleEndian.PutUint32(wire[12:], testCase.messageLength)
			binary.LittleEndian.PutUint32(wire[32:], uint32(Methodinvocation))
			binary.LittleEndian.PutUint32(wire[36:], testCase.auxLength)
			binary.LittleEndian.PutUint32(wire[40:], testCase.totalLength)
			binary.LittleEndian.PutUint32(wire[56:], testCase.auxSize)

			if _, _, err := DecodeNonBlocking(wire); err == nil {
				t.Fatal("DecodeNonBlocking() error = nil, want malformed length rejection")
			}
			if _, err := ReadMessage(bytes.NewReader(wire)); err == nil {
				t.Fatal("ReadMessage() error = nil, want malformed length rejection")
			}
		})
	}
}

func TestPayloadLengthDoesNotUnderflow(t *testing.T) {
	msg := Message{PayloadHeader: PayloadHeader{TotalPayloadLength: 1, AuxiliaryLength: 2}}
	if got := msg.PayloadLength(); got != 0 {
		t.Fatalf("PayloadLength() = %d, want 0", got)
	}
}

func TestConnectionErrIsSafeDuringConcurrentClose(t *testing.T) {
	rwc := newBlockingReadWriteCloser()
	conn, err := newDtxConnection(ios.NewDeviceConnectionWithRWC(rwc))
	if err != nil {
		t.Fatalf("newDtxConnection() error = %v", err)
	}

	start := make(chan struct{})
	var readers sync.WaitGroup
	for range 32 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			<-start
			for range 1000 {
				_ = conn.Err()
			}
		}()
	}
	close(start)
	if err := conn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	readers.Wait()
	if !errors.Is(conn.Err(), ErrConnectionClosed) {
		t.Fatalf("connection error = %v, want ErrConnectionClosed", conn.Err())
	}
}

func TestRequestChannelIdentifierFailureReturnsNoChannel(t *testing.T) {
	writeErr := errors.New("channel request write failed")
	rwc := newRecordingReadWriteCloser(0, writeErr)
	conn, err := newDtxConnection(ios.NewDeviceConnectionWithRWC(rwc))
	if err != nil {
		t.Fatalf("newDtxConnection() error = %v", err)
	}

	channel, err := conn.RequestChannelIdentifierWithError("failing-channel", nil)
	if channel != nil {
		t.Fatalf("channel = %v, want nil", channel)
	}
	if !errors.Is(err, writeErr) {
		t.Fatalf("RequestChannelIdentifierWithError() error = %v, want %v", err, writeErr)
	}
	if _, ok := conn.activeChannels.Load(1); ok {
		t.Fatal("failed channel remained registered")
	}
	if channel := conn.RequestChannelIdentifier("legacy-failing-channel", nil); channel != nil {
		t.Fatalf("legacy RequestChannelIdentifier() channel = %v, want nil", channel)
	}
}
