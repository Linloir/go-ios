package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/Masterminds/semver"
	"github.com/danielpaulus/go-ios/ios"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

var netClient = &http.Client{
	Timeout: time.Millisecond * 200,
}

func CloseAgent() error {
	_, err := netClient.Get(fmt.Sprintf("http://%s:%d/shutdown", ios.HttpApiHost(), ios.HttpApiPort()))
	if err != nil {
		return fmt.Errorf("CloseAgent: failed to send shutdown request: %w", err)
	}
	return nil
}

func IsAgentRunning() bool {
	resp, err := netClient.Get(fmt.Sprintf("http://%s:%d/health", ios.HttpApiHost(), ios.HttpApiPort()))
	if err != nil {
		return false
	}
	return resp.StatusCode == http.StatusOK
}
func WaitUntilAgentReady() bool {
	for {
		slog.Info("Waiting for go-ios agent to be ready...")
		resp, err := netClient.Get(fmt.Sprintf("http://%s:%d/ready", ios.HttpApiHost(), ios.HttpApiPort()))
		if err != nil {
			return false
		}
		if resp.StatusCode == http.StatusOK {
			slog.Info("Go-iOS Agent is ready")
			return true
		}
	}
}

func RunAgent(mode string, args ...string) error {
	if IsAgentRunning() {
		return nil
	}
	slog.Info("Go-iOS Agent not running, starting it on port", "port", ios.HttpApiPort())
	ex, err := os.Executable()
	if err != nil {
		return fmt.Errorf("RunAgent: failed to get executable path: %w", err)
	}

	var cmd *exec.Cmd
	switch mode {
	case "kernel":
		cmd = exec.Command(ex, append([]string{"tunnel", "start"}, args...)...)
	case "user":
		cmd = exec.Command(ex, append([]string{"tunnel", "start", "--userspace"}, args...)...)
	default:
		return fmt.Errorf("RunAgent: unknown mode: %s. Only 'kernel' and 'user' are supported", mode)
	}

	// OS specific SysProcAttr assignment
	cmd.SysProcAttr = createSysProcAttr()

	err = cmd.Start()

	if err != nil {
		return fmt.Errorf("RunAgent: failed to start agent: %w", err)
	}
	err = cmd.Process.Release()
	if err != nil {
		return fmt.Errorf("RunAgent: failed to release process: %w", err)
	}
	WaitUntilAgentReady()
	return nil
}

// ServeTunnelInfo starts a simple http serve that exposes the tunnel information about the running tunnel.
// The API has two endpoints:
// 1. GET    localhost:{PORT}/tunnel/{UDID} to get the tunnel info for a specific device
// 2. DELETE localhost:{PORT}/tunnel/{UDID} to stop a device tunnel
// 3. GET    localhost:{PORT}/tunnels       to get a list of all tunnels
func ServeTunnelInfo(tm *TunnelManager, port int) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/ready", func(writer http.ResponseWriter, request *http.Request) {
		if tm.FirstUpdateCompleted() {
			writer.WriteHeader(http.StatusOK)
		} else {
			writer.WriteHeader(http.StatusServiceUnavailable)
		}
	})
	mux.HandleFunc("/shutdown", func(writer http.ResponseWriter, request *http.Request) {
		err := tm.Close()
		if err != nil {
			log.Error("failed to close tunnel manager", err)
		}
		writer.WriteHeader(http.StatusOK)
		writer.Write([]byte("shutting down in 1 second..."))
		go func() {
			time.Sleep(1 * time.Second)
			os.Exit(0)
		}()
	})
	mux.HandleFunc("/tunnel/", func(writer http.ResponseWriter, request *http.Request) {
		udid := strings.TrimPrefix(request.URL.Path, "/tunnel/")
		if len(udid) == 0 {
			return
		}

		t, err := tm.FindTunnel(udid)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(t.Udid) == 0 {
			http.Error(writer, "", http.StatusNotFound)
			return
		}

		if request.Method == "GET" {
			writer.Header().Add("Content-Type", "application/json")
			enc := json.NewEncoder(writer)
			err = enc.Encode(t)
		} else if request.Method == "DELETE" {
			err = tm.stopTunnel(t)
		}
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
	})
	mux.HandleFunc("/tunnels", func(writer http.ResponseWriter, request *http.Request) {
		tunnels, err := tm.ListTunnels()
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		writer.Header().Add("Content-Type", "application/json")
		enc := json.NewEncoder(writer)
		err = enc.Encode(tunnels)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
	})
	if err := http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", port), mux); err != nil {
		return fmt.Errorf("ServeTunnelInfo: failed to start http server: %w", err)
	}
	return nil
}

func TunnelInfoForDevice(udid string, tunnelInfoHost string, tunnelInfoPort int) (Tunnel, error) {
	c := http.Client{
		Timeout: 5 * time.Second,
	}
	res, err := c.Get(fmt.Sprintf("http://%s:%d/tunnel/%s", tunnelInfoHost, tunnelInfoPort, udid))
	if err != nil {
		return Tunnel{}, fmt.Errorf("TunnelInfoForDevice: failed to get tunnel info: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return Tunnel{}, fmt.Errorf("TunnelInfoForDevice: failed to read body: %w", err)
	}
	var info Tunnel
	err = json.Unmarshal(body, &info)
	if err != nil {
		return Tunnel{}, fmt.Errorf("TunnelInfoForDevice: failed to parse response: %w", err)
	}
	return info, nil
}

func ListRunningTunnels(tunnelInfoHost string, tunnelInfoPort int) ([]Tunnel, error) {
	c := http.Client{
		Timeout: 5 * time.Second,
	}
	res, err := c.Get(fmt.Sprintf("http://%s:%d/tunnels", tunnelInfoHost, tunnelInfoPort))
	if err != nil {
		return nil, fmt.Errorf("TunnelInfoForDevice: failed to get tunnel info: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("TunnelInfoForDevice: failed to read body: %w", err)
	}
	var info []Tunnel
	err = json.Unmarshal(body, &info)
	if err != nil {
		return nil, fmt.Errorf("TunnelInfoForDevice: failed to parse response: %w", err)
	}
	return info, nil
}

// TunnelManager starts tunnels for devices when needed (if no tunnel is running yet) and stores the information
// how those tunnels are reachable (address and remote service discovery port)
type TunnelManager struct {
	ts                   tunnelStarter
	dl                   deviceLister
	pm                   PairRecordManager
	mux                  sync.RWMutex
	updateMux            sync.Mutex
	tunnels              map[string]Tunnel
	startTunnelTimeout   time.Duration
	getProductVersion    func(ios.DeviceEntry) (*semver.Version, error)
	firstUpdateCompleted bool
	userspaceTUN         bool
	closeOnce            sync.Once
	closeErr             error
	closed               bool
	portOffset           int
}

// NewTunnelManager creates a new TunnelManager instance for setting up device tunnels for all connected devices
// If userspaceTUN is set to true, the network stack will run in user space.
func NewTunnelManager(pm PairRecordManager, userspaceTUN bool) *TunnelManager {
	return &TunnelManager{
		ts:                 manualPairingTunnelStart{},
		dl:                 deviceList{},
		pm:                 pm,
		tunnels:            map[string]Tunnel{},
		startTunnelTimeout: 10 * time.Second,
		getProductVersion:  ios.GetProductVersion,
		userspaceTUN:       userspaceTUN,
		portOffset:         1,
	}
}

func (m *TunnelManager) Close() error {
	m.closeOnce.Do(func() {
		// Do not race shutdown against a full device-list update.
		m.updateMux.Lock()
		defer m.updateMux.Unlock()

		m.mux.Lock()
		m.closed = true
		tunnels := maps.Values(m.tunnels)
		m.tunnels = map[string]Tunnel{}
		m.mux.Unlock()

		for _, t := range tunnels {
			err := t.Close()
			m.closeErr = errors.Join(m.closeErr, err)
			if err != nil {
				log.WithField("udid", t.Udid).Error("failed to stop tunnel", err)
			}
		}
	})
	return m.closeErr
}

// FirstUpdateCompleted returns true if the first update completed,
// use it to prevent race conditions when trying to use go-ios agent for the first time
func (m *TunnelManager) FirstUpdateCompleted() bool {
	m.mux.RLock()
	defer m.mux.RUnlock()
	return m.firstUpdateCompleted
}

// UpdateTunnels checks for connected devices and starts a new tunnel if needed
// On device disconnects the tunnel resources get cleaned up
func (m *TunnelManager) UpdateTunnels(ctx context.Context) error {
	m.updateMux.Lock()
	defer m.updateMux.Unlock()

	m.mux.RLock()
	if m.closed {
		m.mux.RUnlock()
		return errors.New("UpdateTunnels: tunnel manager is closed")
	}
	localTunnels := map[string]Tunnel{}
	maps.Copy(localTunnels, m.tunnels)
	m.mux.RUnlock()

	devices, err := m.dl.ListDevices()
	if err != nil {
		return fmt.Errorf("UpdateTunnels: failed to get list of devices: %w", err)
	}
	var updateErr error
	for _, d := range devices.DeviceList {
		udid := d.Properties.SerialNumber
		if _, exists := localTunnels[udid]; exists {
			continue
		}
		if m.userspaceTUN && d.UserspaceTUNPort == 0 {
			d.UserspaceTUNPort = m.nextUserspaceTUNPort()
		}
		t, err := m.startTunnel(ctx, d)
		if err != nil {
			updateErr = errors.Join(updateErr, fmt.Errorf("start tunnel for %s: %w", udid, err))
			log.WithField("udid", udid).
				WithError(err).
				Warn("failed to start tunnel")
			continue
		}
		// The map key and serialized tunnel identity must always describe the
		// device we just reconciled, even if a starter omitted the field.
		t.Udid = udid
		m.mux.Lock()
		localTunnels[udid] = t
		m.tunnels[udid] = t
		m.mux.Unlock()
	}
	for udid, tun := range localTunnels {
		idx := slices.ContainsFunc(devices.DeviceList, func(entry ios.DeviceEntry) bool {
			return entry.Properties.SerialNumber == udid
		})
		if !idx {
			if err := m.stopTunnel(tun); err != nil {
				updateErr = errors.Join(updateErr, fmt.Errorf("stop tunnel for %s: %w", udid, err))
			}
		}
	}
	if updateErr == nil {
		m.mux.Lock()
		m.firstUpdateCompleted = true
		m.mux.Unlock()
	}
	return updateErr
}

func (m *TunnelManager) RemoveTunnel(ctx context.Context, serialNumber string) error {
	m.mux.RLock()
	tun, ok := m.tunnels[serialNumber]
	m.mux.RUnlock()
	if !ok {
		return errors.New("tunnel not found")
	}
	return m.stopTunnel(tun)
}

func (m *TunnelManager) stopTunnel(t Tunnel) error {
	m.mux.Lock()
	current, exists := m.tunnels[t.Udid]
	if exists {
		delete(m.tunnels, t.Udid)
	}
	m.mux.Unlock()
	if !exists {
		return nil
	}

	log.WithField("udid", t.Udid).Info("stopping tunnel")
	return current.Close()
}

func (m *TunnelManager) nextUserspaceTUNPort() int {
	m.mux.Lock()
	defer m.mux.Unlock()
	port := ios.HttpApiPort() + m.portOffset
	m.portOffset++
	return port
}

func (m *TunnelManager) startTunnel(ctx context.Context, device ios.DeviceEntry) (Tunnel, error) {
	log.WithField("udid", device.Properties.SerialNumber).Info("start tunnel")
	startTunnelCtx, cancel := context.WithTimeout(ctx, m.startTunnelTimeout)
	defer cancel()
	getProductVersion := m.getProductVersion
	if getProductVersion == nil {
		getProductVersion = ios.GetProductVersion
	}
	version, err := getProductVersion(device)
	if err != nil {
		return Tunnel{}, fmt.Errorf("startTunnel: failed to get device version: %w", err)
	}
	t, err := m.ts.StartTunnel(startTunnelCtx, device, m.pm, version, m.userspaceTUN)
	if err != nil {
		return Tunnel{}, err
	}
	return t, nil
}

// ListTunnels provides all currently running device tunnels
func (m *TunnelManager) ListTunnels() ([]Tunnel, error) {
	m.mux.RLock()
	defer m.mux.RUnlock()
	return maps.Values(m.tunnels), nil
}

func (m *TunnelManager) FindTunnel(udid string) (Tunnel, error) {
	m.mux.RLock()
	defer m.mux.RUnlock()
	if tunnel, ok := m.tunnels[udid]; ok {
		return tunnel, nil
	}
	return Tunnel{}, nil
}

type tunnelStarter interface {
	StartTunnel(ctx context.Context, device ios.DeviceEntry, p PairRecordManager, version *semver.Version, userspaceTUN bool) (Tunnel, error)
}

type deviceLister interface {
	ListDevices() (ios.DeviceList, error)
}

type manualPairingTunnelStart struct {
}

func (m manualPairingTunnelStart) StartTunnel(ctx context.Context, device ios.DeviceEntry, p PairRecordManager, version *semver.Version, userspaceTUN bool) (Tunnel, error) {

	if version.GreaterThan(semver.MustParse("17.4.0")) {
		if userspaceTUN {
			tun, err := ConnectUserSpaceTunnelLockdown(device, device.UserspaceTUNPort)
			tun.UserspaceTUN = true
			tun.UserspaceTUNPort = device.UserspaceTUNPort
			return tun, err
		}
		return ConnectTunnelLockdown(device)
	}
	if version.Major() >= 17 {
		if userspaceTUN {
			return Tunnel{}, errors.New("manualPairingTunnelStart: userspaceTUN not supported for iOS >=17 and < 17.4")
		}
		return ManualPairAndConnectToTunnel(ctx, device, p)
	}
	return Tunnel{}, fmt.Errorf("manualPairingTunnelStart: unsupported iOS version %s", version.String())
}

type deviceList struct {
}

func (d deviceList) ListDevices() (ios.DeviceList, error) {
	return ios.ListDevices()
}
