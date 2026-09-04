package testmanagerd

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	dtx "github.com/danielpaulus/go-ios/ios/dtx_codec"
)

type recordingProxyDTXConnection struct {
	mu           sync.Mutex
	sent         [][]byte
	sendAttempts int
	sendErr      error
	closeCount   int
	closed       chan struct{}
	closeOnce    sync.Once
}

func newRecordingProxyDTXConnection() *recordingProxyDTXConnection {
	return &recordingProxyDTXConnection{closed: make(chan struct{})}
}

func (c *recordingProxyDTXConnection) Send(message []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sendAttempts++
	if c.sendErr != nil {
		return c.sendErr
	}
	c.sent = append(c.sent, append([]byte(nil), message...))
	return nil
}

func (c *recordingProxyDTXConnection) Close() error {
	c.mu.Lock()
	c.closeCount++
	c.mu.Unlock()
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *recordingProxyDTXConnection) Closed() <-chan struct{} {
	return c.closed
}

func (c *recordingProxyDTXConnection) snapshot() ([][]byte, int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.sent...), c.sendAttempts, c.closeCount
}

func TestDuplicateBundleReadyNotificationDoesNotBlockDispatcher(t *testing.T) {
	ready := make(chan dtx.Message, 1)
	dispatcher := proxyDispatcher{
		testBundleReadyChannel: ready,
		dtxConnection:          &dtx.Connection{},
	}
	message := dtx.Message{Payload: []interface{}{"_XCT_testBundleReadyWithProtocolVersion:minimumVersion:"}}

	dispatcher.Dispatch(message)
	dispatched := make(chan struct{})
	go func() {
		dispatcher.Dispatch(message)
		close(dispatched)
	}()

	select {
	case <-dispatched:
	case <-time.After(time.Second):
		t.Fatal("duplicate bundle-ready notification blocked the DTX dispatcher")
	}
	if got := len(ready); got != 1 {
		t.Fatalf("ready notification count = %d, want 1", got)
	}
}

func TestDispatcherAcknowledgesMalformedAndPanickingMessages(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		payload []interface{}
	}{
		{name: "invalid selector", payload: []interface{}{uint64(42)}},
		{name: "panicking callback", payload: []interface{}{"_XCT_didFinishExecutingTestPlan"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			connection := newRecordingProxyDTXConnection()
			message := dtx.Message{
				Identifier:        17,
				ConversationIndex: 3,
				ChannelCode:       9,
				ExpectsReply:      true,
				Payload:           testCase.payload,
			}
			dispatcher := proxyDispatcher{dtxConnection: connection}

			dispatcher.Dispatch(message)

			sent, attempts, closes := connection.snapshot()
			if attempts != 1 || len(sent) != 1 {
				t.Fatalf("ACK sends = %d successful = %d, want 1/1", attempts, len(sent))
			}
			if !bytes.Equal(sent[0], dtx.BuildAckMessage(message)) {
				t.Fatal("dispatcher sent an unexpected ACK")
			}
			if closes != 0 {
				t.Fatalf("connection closes = %d, want 0", closes)
			}
		})
	}
}

func TestCapabilitiesResponseFailureTerminatesSession(t *testing.T) {
	sendFailure := errors.New("send failed")
	handlerFailure := errors.New("handler failed")
	for _, testCase := range []struct {
		name             string
		handler          dtx.MethodWithResponse
		sendErr          error
		wantSendAttempts int
	}{
		{
			name: "handler failure",
			handler: func(dtx.Message) (interface{}, error) {
				return nil, handlerFailure
			},
		},
		{
			name: "archive panic",
			handler: func(dtx.Message) (interface{}, error) {
				return make(chan struct{}), nil
			},
		},
		{
			name: "send failure",
			handler: func(dtx.Message) (interface{}, error) {
				return "capabilities", nil
			},
			sendErr:          sendFailure,
			wantSendAttempts: 1,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			connection := newRecordingProxyDTXConnection()
			connection.sendErr = testCase.sendErr
			listener := NewTestListener(bytes.NewBuffer(nil), bytes.NewBuffer(nil), t.TempDir())
			dispatcher := proxyDispatcher{
				dtxConnection:                   connection,
				testListener:                    listener,
				testRunnerReadyWithCapabilities: testCase.handler,
			}
			message := dtx.Message{
				Identifier:   17,
				ChannelCode:  9,
				ExpectsReply: true,
				Payload:      []interface{}{"_XCT_testRunnerReadyWithCapabilities:"},
			}

			dispatcher.Dispatch(message)

			select {
			case <-listener.Done():
			case <-time.After(time.Second):
				t.Fatal("terminal capabilities response failure did not finish listener")
			}
			_, listenerErr := listener.Result()
			if listenerErr == nil {
				t.Fatal("listener error = nil, want terminal response failure")
			}
			_, attempts, closes := connection.snapshot()
			if attempts != testCase.wantSendAttempts {
				t.Fatalf("send attempts = %d, want %d", attempts, testCase.wantSendAttempts)
			}
			if closes != 1 {
				t.Fatalf("connection closes = %d, want 1", closes)
			}
		})
	}
}
