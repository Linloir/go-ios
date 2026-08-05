package tunnel

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Masterminds/semver"
	"github.com/danielpaulus/go-ios/ios"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTunnelManagerSerializesUpdates(t *testing.T) {
	lister := &concurrencyDetectingDeviceLister{}
	manager := NewTunnelManager(PairRecordManager{}, false)
	manager.dl = lister

	const updates = 24
	var wg sync.WaitGroup
	errs := make(chan error, updates)
	for i := 0; i < updates; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- manager.UpdateTunnels(context.Background())
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	assert.Equal(t, int64(1), lister.maxActive.Load())
	assert.True(t, manager.FirstUpdateCompleted())
}

func TestTunnelManagerDoesNotReportReadyAfterTunnelStartFailure(t *testing.T) {
	wantErr := errors.New("start failed")
	device := ios.DeviceEntry{Properties: ios.DeviceProperties{SerialNumber: "device"}}
	manager := NewTunnelManager(PairRecordManager{}, false)
	manager.dl = staticDeviceLister{devices: ios.DeviceList{DeviceList: []ios.DeviceEntry{device}}}
	manager.getProductVersion = func(ios.DeviceEntry) (*semver.Version, error) {
		return semver.MustParse("17.5.0"), nil
	}
	manager.ts = tunnelStarterFunc(func(context.Context, ios.DeviceEntry, PairRecordManager, *semver.Version, bool) (Tunnel, error) {
		return Tunnel{}, wantErr
	})

	err := manager.UpdateTunnels(context.Background())
	assert.ErrorIs(t, err, wantErr)
	assert.False(t, manager.FirstUpdateCompleted())
}

func TestTunnelManagerBecomesReadyAfterFailedTunnelIsStarted(t *testing.T) {
	wantErr := errors.New("start failed")
	device := ios.DeviceEntry{Properties: ios.DeviceProperties{SerialNumber: "device"}}
	manager := NewTunnelManager(PairRecordManager{}, false)
	manager.dl = staticDeviceLister{devices: ios.DeviceList{DeviceList: []ios.DeviceEntry{device}}}
	manager.getProductVersion = func(ios.DeviceEntry) (*semver.Version, error) {
		return semver.MustParse("17.5.0"), nil
	}
	var attempts atomic.Int64
	manager.ts = tunnelStarterFunc(func(context.Context, ios.DeviceEntry, PairRecordManager, *semver.Version, bool) (Tunnel, error) {
		if attempts.Add(1) == 1 {
			return Tunnel{}, wantErr
		}
		return Tunnel{closer: func() error { return nil }}, nil
	})

	assert.ErrorIs(t, manager.UpdateTunnels(context.Background()), wantErr)
	assert.False(t, manager.FirstUpdateCompleted())
	require.NoError(t, manager.UpdateTunnels(context.Background()))
	assert.True(t, manager.FirstUpdateCompleted())
	tunnel, err := manager.FindTunnel("device")
	require.NoError(t, err)
	assert.Equal(t, "device", tunnel.Udid)
}

func TestTunnelManagerUserspacePortAllocationIsConcurrentSafe(t *testing.T) {
	manager := NewTunnelManager(PairRecordManager{}, true)
	const allocations = 256
	ports := make(chan int, allocations)

	var wg sync.WaitGroup
	for i := 0; i < allocations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ports <- manager.nextUserspaceTUNPort()
		}()
	}
	wg.Wait()
	close(ports)

	unique := make(map[int]struct{}, allocations)
	for port := range ports {
		if _, exists := unique[port]; exists {
			t.Fatalf("duplicate userspace TUN port allocated: %d", port)
		}
		unique[port] = struct{}{}
	}
	assert.Len(t, unique, allocations)
}

func TestTunnelManagerConcurrentListFindAndRemove(t *testing.T) {
	manager := NewTunnelManager(PairRecordManager{}, false)
	const tunnelCount = 32
	var closeCalls atomic.Int64
	errs := make(chan error, 8*500+tunnelCount)
	for i := 0; i < tunnelCount; i++ {
		udid := fmt.Sprintf("device-%d", i)
		manager.tunnels[udid] = Tunnel{
			Udid: udid,
			closer: func() error {
				closeCalls.Add(1)
				return nil
			},
		}
	}

	var wg sync.WaitGroup
	for reader := 0; reader < 8; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				_, err := manager.ListTunnels()
				if err != nil {
					errs <- err
				}
				_, err = manager.FindTunnel(fmt.Sprintf("device-%d", i%tunnelCount))
				if err != nil {
					errs <- err
				}
				_ = manager.FirstUpdateCompleted()
			}
		}()
	}
	for i := 0; i < tunnelCount; i++ {
		udid := fmt.Sprintf("device-%d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := manager.RemoveTunnel(context.Background(), udid); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	tunnels, err := manager.ListTunnels()
	require.NoError(t, err)
	assert.Empty(t, tunnels)
	assert.Equal(t, int64(tunnelCount), closeCalls.Load())
}

func TestTunnelManagerCloseIsIdempotentAndPreservesError(t *testing.T) {
	wantErr := errors.New("close failed")
	manager := NewTunnelManager(PairRecordManager{}, false)
	manager.tunnels["device"] = Tunnel{
		Udid:   "device",
		closer: func() error { return wantErr },
	}

	assert.ErrorIs(t, manager.Close(), wantErr)
	assert.ErrorIs(t, manager.Close(), wantErr)
	tunnels, err := manager.ListTunnels()
	require.NoError(t, err)
	assert.Empty(t, tunnels)
	assert.Error(t, manager.UpdateTunnels(context.Background()))
}

func TestStopTunnelClosesCurrentMapEntry(t *testing.T) {
	manager := NewTunnelManager(PairRecordManager{}, false)
	var staleCloseCalls atomic.Int64
	var currentCloseCalls atomic.Int64
	stale := Tunnel{
		Udid:   "device",
		closer: func() error { staleCloseCalls.Add(1); return nil },
	}
	manager.tunnels["device"] = Tunnel{
		Udid:   "device",
		closer: func() error { currentCloseCalls.Add(1); return nil },
	}

	require.NoError(t, manager.stopTunnel(stale))
	assert.Zero(t, staleCloseCalls.Load())
	assert.Equal(t, int64(1), currentCloseCalls.Load())
}

type concurrencyDetectingDeviceLister struct {
	active    atomic.Int64
	maxActive atomic.Int64
}

type staticDeviceLister struct {
	devices ios.DeviceList
	err     error
}

func (l staticDeviceLister) ListDevices() (ios.DeviceList, error) {
	return l.devices, l.err
}

type tunnelStarterFunc func(context.Context, ios.DeviceEntry, PairRecordManager, *semver.Version, bool) (Tunnel, error)

func (f tunnelStarterFunc) StartTunnel(ctx context.Context, device ios.DeviceEntry, pairRecordManager PairRecordManager, version *semver.Version, userspaceTUN bool) (Tunnel, error) {
	return f(ctx, device, pairRecordManager, version, userspaceTUN)
}

func (l *concurrencyDetectingDeviceLister) ListDevices() (ios.DeviceList, error) {
	active := l.active.Add(1)
	defer l.active.Add(-1)
	for {
		max := l.maxActive.Load()
		if active <= max || l.maxActive.CompareAndSwap(max, active) {
			break
		}
	}
	time.Sleep(time.Millisecond)
	return ios.DeviceList{}, nil
}
