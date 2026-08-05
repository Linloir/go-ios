// Package pasteboard provides access to the general pasteboard on iOS 17+
// devices through the RemoteXPC pasteboard service.
package pasteboard

import (
	"fmt"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/xpc"
)

const (
	// ServiceName is the RemoteXPC pasteboard service exposed through RSD.
	ServiceName = "com.apple.coredevice.pasteboardservice"
	// GeneralPasteboard is the default system pasteboard.
	GeneralPasteboard = "general"

	// UTIUTF8PlainText, UTIPlainText, and UTIText are the standard text UTIs
	// published for text written through SetText.
	UTIUTF8PlainText = "public.utf8-plain-text"
	UTIPlainText     = "public.plain-text"
	UTIText          = "public.text"
)

const (
	pasteboardCommandPull = "PULL"
	pasteboardCommandSet  = "SET"
	requestTimeout        = 10 * time.Second
)

var textUTIs = []string{UTIUTF8PlainText, UTIPlainText, UTIText}

// Connection is a non-concurrent-safe connection to pasteboardservice.
type Connection struct {
	conn    *xpc.Connection
	timeout time.Duration
}

// New connects to pasteboardservice. The device must have an active iOS 17+
// tunnel and an RSD entry for ServiceName.
func New(device ios.DeviceEntry) (*Connection, error) {
	conn, err := ios.ConnectToXpcServiceTunnelIface(device, ServiceName)
	if err != nil {
		return nil, fmt.Errorf("pasteboard New: %w", err)
	}
	return &Connection{conn: conn, timeout: requestTimeout}, nil
}

// Close closes the RemoteXPC connection.
func (c *Connection) Close() error {
	return c.conn.Close()
}

// SetText replaces the general pasteboard with a single UTF-8 text item.
func (c *Connection) SetText(text string) error {
	if _, err := c.sendReceive(buildSetTextRequest(text)); err != nil {
		return fmt.Errorf("SetText: %w", err)
	}
	return nil
}

// GetText returns the first resolved text item on the general pasteboard. The
// bool result is false when the snapshot contains no inline text value.
func (c *Connection) GetText() (string, bool, error) {
	reply, err := c.sendReceive(buildPullRequest())
	if err != nil {
		return "", false, fmt.Errorf("GetText: %w", err)
	}
	text, ok := snapshotText(reply)
	return text, ok, nil
}

func (c *Connection) sendReceive(request map[string]interface{}) (map[string]interface{}, error) {
	if err := c.conn.Send(request, xpc.HeartbeatRequestFlag); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	type result struct {
		reply map[string]interface{}
		err   error
	}
	resultCh := make(chan result, 1)
	go func() {
		for {
			reply, err := c.conn.ReceiveOnServerClientStream()
			if err != nil || reply != nil {
				resultCh <- result{reply: reply, err: err}
				return
			}
			// RemoteXPC may interleave empty heartbeat frames before the reply.
		}
	}()

	timer := time.NewTimer(c.timeout)
	defer timer.Stop()
	select {
	case result := <-resultCh:
		if result.err != nil {
			return nil, fmt.Errorf("failed to receive reply: %w", result.err)
		}
		return result.reply, nil
	case <-timer.C:
		// The receive API has no context support. Closing the connection is the
		// only way to release its blocked reader; this connection cannot be
		// reused after a timeout.
		_ = c.Close()
		return nil, fmt.Errorf("timed out after %s waiting for pasteboardservice", c.timeout)
	}
}

func buildSetTextRequest(text string) map[string]interface{} {
	payload := []byte(text)
	data := make(map[string]interface{}, len(textUTIs))
	types := make([]interface{}, len(textUTIs))
	for i, uti := range textUTIs {
		data[uti] = map[string]interface{}{"data": payload}
		types[i] = uti
	}
	return map[string]interface{}{
		"command":        pasteboardCommandSet,
		"pasteboardName": GeneralPasteboard,
		"items": []interface{}{
			map[string]interface{}{
				"types": types,
				"data":  data,
			},
		},
		"sourceMetadata": nil,
	}
}

func buildPullRequest() map[string]interface{} {
	return map[string]interface{}{
		"command":        pasteboardCommandPull,
		"pasteboardName": GeneralPasteboard,
		"dataPolicy": map[string]interface{}{
			"allResolved": map[string]interface{}{},
		},
	}
}

// snapshotText accepts both the PULL reply envelope (items below pasteboard)
// and a bare snapshot. Promise-only values are deliberately ignored.
func snapshotText(reply map[string]interface{}) (string, bool) {
	snapshot := reply
	if pasteboard, ok := reply["pasteboard"].(map[string]interface{}); ok {
		snapshot = pasteboard
	}
	items, ok := snapshot["items"].([]interface{})
	if !ok {
		return "", false
	}
	for _, rawItem := range items {
		item, ok := rawItem.(map[string]interface{})
		if !ok {
			continue
		}
		data, ok := item["data"].(map[string]interface{})
		if !ok {
			continue
		}
		for _, uti := range textUTIs {
			datum, ok := data[uti].(map[string]interface{})
			if !ok {
				continue
			}
			if value, ok := datum["data"].([]byte); ok && len(value) > 0 {
				return string(value), true
			}
		}
	}
	return "", false
}
