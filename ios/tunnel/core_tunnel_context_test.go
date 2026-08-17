package tunnel

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type blockingCoreTunnelSetupConn struct {
	writeStarted chan struct{}
	closed       chan struct{}
	startOnce    sync.Once
	closeOnce    sync.Once
}

func newBlockingCoreTunnelSetupConn() *blockingCoreTunnelSetupConn {
	return &blockingCoreTunnelSetupConn{
		writeStarted: make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

func (c *blockingCoreTunnelSetupConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.ErrClosedPipe
}

func (c *blockingCoreTunnelSetupConn) Write([]byte) (int, error) {
	c.startOnce.Do(func() { close(c.writeStarted) })
	<-c.closed
	return 0, io.ErrClosedPipe
}

func (c *blockingCoreTunnelSetupConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func TestLockdownTunnelSetupCancellationUnblocksParameterExchange(t *testing.T) {
	tests := []struct {
		name    string
		connect func(context.Context, io.ReadWriteCloser) (Tunnel, error)
	}{
		{
			name: "kernel",
			connect: func(ctx context.Context, conn io.ReadWriteCloser) (Tunnel, error) {
				return connectToTunnelLockdown(ctx, ios.DeviceEntry{}, conn)
			},
		},
		{
			name: "userspace",
			connect: func(ctx context.Context, conn io.ReadWriteCloser) (Tunnel, error) {
				return connectToUserspaceTunnelLockdown(ctx, ios.DeviceEntry{}, conn, 0)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			conn := newBlockingCoreTunnelSetupConn()
			result := make(chan error, 1)
			go func() {
				_, err := test.connect(ctx, conn)
				result <- err
			}()

			select {
			case <-conn.writeStarted:
			case <-time.After(time.Second):
				t.Fatal("tunnel parameter exchange did not start")
			}
			cancel()

			select {
			case err := <-result:
				require.Error(t, err)
				assert.ErrorIs(t, err, context.Canceled)
			case <-time.After(time.Second):
				t.Fatal("tunnel setup did not return after context cancellation")
			}
			select {
			case <-conn.closed:
			default:
				t.Fatal("tunnel setup connection was not closed on cancellation")
			}
		})
	}
}
