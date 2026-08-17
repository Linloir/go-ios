package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Masterminds/semver"
	"github.com/danielpaulus/go-ios/ios"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type runtimeTestRWC struct {
	readErr    chan error
	closeOnce  sync.Once
	closeCalls atomic.Int64
}

func newRuntimeTestRWC() *runtimeTestRWC {
	return &runtimeTestRWC{readErr: make(chan error, 1)}
}

func (r *runtimeTestRWC) Read([]byte) (int, error) {
	return 0, <-r.readErr
}

func (r *runtimeTestRWC) Write(p []byte) (int, error) {
	return len(p), nil
}

func (r *runtimeTestRWC) Close() error {
	r.closeCalls.Add(1)
	r.closeOnce.Do(func() { r.readErr <- io.ErrClosedPipe })
	return nil
}

func (r *runtimeTestRWC) fail(err error) {
	r.readErr <- err
}

type runtimeTestQUIC struct {
	ctx        context.Context
	cancel     context.CancelCauseFunc
	closeCalls atomic.Int64
}

func newRuntimeTestQUIC() *runtimeTestQUIC {
	ctx, cancel := context.WithCancelCause(context.Background())
	return &runtimeTestQUIC{ctx: ctx, cancel: cancel}
}

func (c *runtimeTestQUIC) SendDatagram([]byte) error { return nil }

func (c *runtimeTestQUIC) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-c.ctx.Done():
		return nil, context.Cause(c.ctx)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *runtimeTestQUIC) CloseWithError(quic.ApplicationErrorCode, string) error {
	c.closeCalls.Add(1)
	c.cancel(io.ErrClosedPipe)
	return nil
}

func (c *runtimeTestQUIC) Context() context.Context { return c.ctx }

func waitForTunnelDone(t *testing.T, tunnel Tunnel) {
	t.Helper()
	select {
	case <-tunnel.Done():
	case <-time.After(time.Second):
		t.Fatal("tunnel workers did not join")
	}
}

func TestQUICKernelRuntimeTransportFailureClosesAndJoinsGeneration(t *testing.T) {
	wantErr := errors.New("QUIC underlay failed")
	conn := newRuntimeTestQUIC()
	utun := newRuntimeTestRWC()
	tunnel := Tunnel{runtime: startQUICKernelTunnelRuntime(context.Background(), conn, utun, 1280)}

	conn.cancel(wantErr)
	waitForTunnelDone(t, tunnel)
	require.ErrorIs(t, tunnel.Err(), wantErr)
	require.NoError(t, tunnel.Close())
	assert.Equal(t, int64(1), conn.closeCalls.Load())
	assert.Equal(t, int64(1), utun.closeCalls.Load())
}

func TestLockdownKernelRuntimeForwardFailureClosesAndJoinsGeneration(t *testing.T) {
	wantErr := errors.New("lockdown receive failed")
	conn := newRuntimeTestRWC()
	utun := newRuntimeTestRWC()
	tunnel := Tunnel{runtime: startLockdownKernelTunnelRuntime(context.Background(), conn, utun, 1280)}

	conn.fail(wantErr)
	waitForTunnelDone(t, tunnel)
	require.ErrorIs(t, tunnel.Err(), wantErr)
	require.NoError(t, tunnel.Close())
	assert.Equal(t, int64(1), conn.closeCalls.Load())
	assert.Equal(t, int64(1), utun.closeCalls.Load())
}

func TestUserspaceRuntimeListenerAndTransportFailuresCloseAndJoinGeneration(t *testing.T) {
	for _, test := range []struct {
		name       string
		failWorker func(chan error, chan struct{}, error)
	}{
		{
			name: "listener",
			failWorker: func(listenerResult chan error, _ chan struct{}, err error) {
				listenerResult <- err
			},
		},
		{
			name: "transport",
			failWorker: func(_ chan error, transportDone chan struct{}, _ error) {
				close(transportDone)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			wantErr := errors.New(test.name + " failed")
			listenerResult := make(chan error, 1)
			transportDone := make(chan struct{})
			var cleanupOnce sync.Once
			var cleanupCalls atomic.Int64
			cleanup := func() error {
				cleanupCalls.Add(1)
				cleanupOnce.Do(func() { listenerResult <- io.ErrClosedPipe })
				return nil
			}
			tunnel := Tunnel{runtime: startUserspaceLockdownTunnelRuntime(
				context.Background(),
				func() error { return <-listenerResult },
				transportDone,
				cleanup,
			)}

			test.failWorker(listenerResult, transportDone, wantErr)
			waitForTunnelDone(t, tunnel)
			if test.name == "listener" {
				require.ErrorIs(t, tunnel.Err(), wantErr)
			} else {
				require.Error(t, tunnel.Err())
			}
			require.NoError(t, tunnel.Close())
			assert.Equal(t, int64(1), cleanupCalls.Load())
		})
	}
}

func TestUserspaceTunnelServerCloseJoinsStalledClient(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := newUserspaceTunnelServer(&UserSpaceTUNInterface{}, listener)
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.serve() }()

	client, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer client.Close()
	require.Eventually(t, func() bool {
		server.mu.Lock()
		defer server.mu.Unlock()
		return len(server.clients) == 1
	}, time.Second, time.Millisecond)

	require.NoError(t, server.close())
	select {
	case err := <-serveDone:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(time.Second):
		t.Fatal("userspace listener did not stop")
	}
	waitDone := make(chan struct{})
	go func() {
		server.wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
	case <-time.After(time.Second):
		t.Fatal("stalled userspace client goroutine did not join")
	}
}

func TestTunnelRuntimeConcurrentCloseIsIdempotentAndJoinsWorkers(t *testing.T) {
	var cleanupCalls atomic.Int64
	runtime := newTunnelRuntime(context.Background(), func() error {
		cleanupCalls.Add(1)
		return nil
	},
		tunnelRuntimeWorker{name: "one", run: func(ctx context.Context) error { <-ctx.Done(); return nil }},
		tunnelRuntimeWorker{name: "two", run: func(ctx context.Context) error { <-ctx.Done(); return nil }},
	)
	tunnel := Tunnel{runtime: runtime}

	const callers = 32
	var wait sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errs <- tunnel.Close()
		}()
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	waitForTunnelDone(t, tunnel)
	assert.Equal(t, int64(1), cleanupCalls.Load())
	assert.NoError(t, tunnel.Err())
}

func TestTunnelManagerRebuildsDeadTunnelWithSameAttachmentAfterJoin(t *testing.T) {
	const udid = "same-attachment-dead-underlay"
	device := ios.DeviceEntry{DeviceID: 77, Properties: ios.DeviceProperties{SerialNumber: udid, LocationID: 88}}
	manager := NewTunnelManager(PairRecordManager{}, false)
	manager.dl = staticDeviceLister{devices: ios.DeviceList{DeviceList: []ios.DeviceEntry{device}}}
	manager.getProductVersion = func(ios.DeviceEntry) (*semver.Version, error) {
		return semver.MustParse("17.5.0"), nil
	}

	failFirst := make(chan error, 1)
	cleanupStarted := make(chan struct{})
	releaseCleanup := make(chan struct{})
	var starts atomic.Int64
	manager.ts = tunnelStarterFunc(func(context.Context, ios.DeviceEntry, PairRecordManager, *semver.Version, bool) (Tunnel, error) {
		attempt := starts.Add(1)
		if attempt == 1 {
			runtime := newTunnelRuntime(context.Background(), func() error {
				close(cleanupStarted)
				<-releaseCleanup
				return nil
			}, tunnelRuntimeWorker{name: "first underlay", run: func(context.Context) error {
				return <-failFirst
			}})
			return Tunnel{Address: "old", runtime: runtime}, nil
		}
		runtime := newTunnelRuntime(context.Background(), func() error { return nil },
			tunnelRuntimeWorker{name: "replacement", run: func(ctx context.Context) error {
				<-ctx.Done()
				return nil
			}})
		return Tunnel{Address: "replacement", runtime: runtime}, nil
	})

	require.NoError(t, manager.UpdateTunnels(context.Background()))
	old, err := manager.FindTunnel(udid)
	require.NoError(t, err)
	wantErr := errors.New("first generation died")
	failFirst <- wantErr
	select {
	case <-cleanupStarted:
	case <-time.After(time.Second):
		t.Fatal("dead generation did not begin cleanup")
	}
	assert.False(t, old.alive())

	updateDone := make(chan error, 1)
	go func() { updateDone <- manager.UpdateTunnels(context.Background()) }()
	select {
	case err := <-updateDone:
		t.Fatalf("replacement completed before the dead generation joined: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	assert.Equal(t, int64(1), starts.Load())

	close(releaseCleanup)
	require.NoError(t, <-updateDone)
	replacement, err := manager.FindTunnel(udid)
	require.NoError(t, err)
	assert.Equal(t, "replacement", replacement.Address)
	assert.Greater(t, replacement.generation, old.generation)
	assert.Equal(t, old.attachment, replacement.attachment)
	assert.Equal(t, int64(2), starts.Load())
	require.NoError(t, manager.Close())
}
