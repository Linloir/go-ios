package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
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

const (
	defaultAgentReadyTimeout = 30 * time.Second
	agentReadyInitialBackoff = 50 * time.Millisecond
	agentReadyMaxBackoff     = time.Second
)

func CloseAgent() error {
	statusCode, err := doAgentRequest(context.Background(), netClient, http.MethodGet, agentAPIURL("/shutdown"))
	if err != nil {
		return fmt.Errorf("CloseAgent: failed to send shutdown request: %w", err)
	}
	if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("CloseAgent: server returned HTTP status %d", statusCode)
	}
	return nil
}

func IsAgentRunning() bool {
	running, _ := IsAgentRunningContext(context.Background())
	return running
}

func IsAgentRunningContext(ctx context.Context) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	statusCode, err := doAgentRequest(ctx, netClient, http.MethodGet, agentAPIURL("/health"))
	if err != nil {
		return false, fmt.Errorf("IsAgentRunning: health request failed: %w", err)
	}
	return statusCode == http.StatusOK, nil
}

// WaitUntilAgentReady preserves the historical boolean API. New callers that
// need diagnostics or a shorter deadline should use WaitUntilAgentReadyContext.
func WaitUntilAgentReady() bool {
	return WaitUntilAgentReadyContext(context.Background()) == nil
}

// WaitUntilAgentReadyContext polls the readiness endpoint with bounded
// exponential backoff. Even a context without a deadline is capped so a dead
// agent cannot leave startup blocked forever.
func WaitUntilAgentReadyContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	waitCtx, cancel := context.WithTimeout(ctx, defaultAgentReadyTimeout)
	defer cancel()
	return waitUntilAgentReady(waitCtx, netClient, agentAPIURL("/ready"), agentReadyInitialBackoff, agentReadyMaxBackoff)
}

func waitUntilAgentReady(ctx context.Context, client *http.Client, readyURL string, initialBackoff, maxBackoff time.Duration) error {
	if initialBackoff <= 0 {
		initialBackoff = time.Millisecond
	}
	if maxBackoff < initialBackoff {
		maxBackoff = initialBackoff
	}

	backoff := initialBackoff
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			return agentReadyWaitError(err, lastErr)
		}
		slog.Info("Waiting for go-ios agent to be ready...")
		statusCode, err := doAgentRequest(ctx, client, http.MethodGet, readyURL)
		if err == nil && statusCode == http.StatusOK {
			slog.Info("Go-iOS Agent is ready")
			return nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("server returned HTTP status %d", statusCode)
		}

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return agentReadyWaitError(ctx.Err(), lastErr)
		case <-timer.C:
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

func agentReadyWaitError(contextErr, lastErr error) error {
	if lastErr == nil {
		return fmt.Errorf("WaitUntilAgentReady: %w", contextErr)
	}
	return fmt.Errorf("WaitUntilAgentReady: %w", errors.Join(contextErr, lastErr))
}

func agentAPIURL(path string) string {
	return tunnelInfoURL(ios.HttpApiHost(), ios.HttpApiPort(), path)
}

func doAgentRequest(ctx context.Context, client *http.Client, method, requestURL string) (int, error) {
	request, err := http.NewRequestWithContext(ctx, method, requestURL, nil)
	if err != nil {
		return 0, err
	}
	response, err := client.Do(request)
	if err != nil {
		if response != nil {
			_ = drainAndCloseResponse(response)
		}
		return 0, err
	}
	statusCode := response.StatusCode
	if err := drainAndCloseResponse(response); err != nil {
		return statusCode, err
	}
	return statusCode, nil
}

func drainAndCloseResponse(response *http.Response) error {
	if response == nil || response.Body == nil {
		return nil
	}
	_, drainErr := io.Copy(io.Discard, response.Body)
	closeErr := response.Body.Close()
	return errors.Join(drainErr, closeErr)
}

const agentAutoStartEnvironment = "ENABLE_GO_IOS_AGENT"

type agentChildProcess interface {
	Release() error
	Kill() error
	Wait() error
	Done() <-chan struct{}
}

type execAgentChildProcess struct {
	command  *exec.Cmd
	waitOnce sync.Once
	waitDone chan struct{}
	waitErr  error
}

func (p *execAgentChildProcess) Release() error {
	// The asynchronous waiter started by newExecAgentChildProcess owns process
	// cleanup. Process.Release is deliberately not used: on Unix it does not reap
	// a child that already exited after losing a concurrent listener race.
	return nil
}

func (p *execAgentChildProcess) Kill() error {
	return p.command.Process.Kill()
}

func (p *execAgentChildProcess) Wait() error {
	p.waitOnce.Do(func() {
		p.waitErr = p.command.Wait()
		close(p.waitDone)
	})
	<-p.waitDone
	return p.waitErr
}

func (p *execAgentChildProcess) Done() <-chan struct{} {
	return p.waitDone
}

func newExecAgentChildProcess(command *exec.Cmd) *execAgentChildProcess {
	child := &execAgentChildProcess{command: command, waitDone: make(chan struct{})}
	// Begin waiting immediately so an early-exiting loser is always reaped, even
	// if /ready is served by another concurrently started process.
	go child.Wait()
	return child
}

type runAgentOperations struct {
	isRunning  func(context.Context) (bool, error)
	waitReady  func(context.Context) error
	executable func() (string, error)
	start      func(string, []string) (agentChildProcess, error)
}

func defaultRunAgentOperations() runAgentOperations {
	return runAgentOperations{
		isRunning:  IsAgentRunningContext,
		waitReady:  WaitUntilAgentReadyContext,
		executable: os.Executable,
		start: func(executable string, arguments []string) (agentChildProcess, error) {
			command := newAgentCommand(executable, arguments)
			if err := command.Start(); err != nil {
				return nil, err
			}
			return newExecAgentChildProcess(command), nil
		},
	}
}

func newAgentCommand(executable string, arguments []string) *exec.Cmd {
	command := exec.Command(executable, arguments...)
	command.SysProcAttr = createSysProcAttr()
	// The child is the agent. Letting it inherit the auto-start switch makes it
	// enter RunAgent again before its own command dispatch and recursively spawn
	// more children while /health is still unavailable.
	command.Env = environmentWithoutKey(os.Environ(), agentAutoStartEnvironment)
	return command
}

func environmentWithoutKey(environment []string, key string) []string {
	filtered := make([]string, 0, len(environment))
	for _, entry := range environment {
		entryKey, _, found := strings.Cut(entry, "=")
		if found && strings.EqualFold(entryKey, key) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func RunAgent(mode string, args ...string) error {
	return runAgent(context.Background(), mode, args, defaultRunAgentOperations())
}

func runAgent(ctx context.Context, mode string, args []string, operations runAgentOperations) error {
	if ctx == nil {
		ctx = context.Background()
	}

	running, healthErr := operations.isRunning(ctx)
	if healthErr == nil && running {
		// /health is liveness only. An existing agent can still be rebuilding its
		// first device snapshot, so callers must not proceed until /ready succeeds.
		if err := operations.waitReady(ctx); err != nil {
			return fmt.Errorf("RunAgent: existing agent did not become ready: %w", err)
		}
		return nil
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("RunAgent: check agent health: %w", errors.Join(err, healthErr))
	}

	var commandArguments []string
	switch mode {
	case "kernel":
		commandArguments = append([]string{"tunnel", "start"}, args...)
	case "user":
		commandArguments = append([]string{"tunnel", "start", "--userspace"}, args...)
	default:
		return fmt.Errorf("RunAgent: unknown mode: %s. Only 'kernel' and 'user' are supported", mode)
	}

	slog.Info("Go-iOS Agent not running, starting it on port", "port", ios.HttpApiPort(), "healthError", healthErr)
	executable, err := operations.executable()
	if err != nil {
		return fmt.Errorf("RunAgent: failed to get executable path: %w", err)
	}
	child, err := operations.start(executable, commandArguments)
	if err != nil {
		return fmt.Errorf("RunAgent: failed to start agent: %w", err)
	}

	readyResult := make(chan error, 1)
	go func() {
		readyResult <- operations.waitReady(ctx)
	}()

	select {
	case readyErr := <-readyResult:
		if readyErr == nil {
			// Release only after readiness. The production implementation transfers
			// ownership to its already-running asynchronous reaper.
			if err := child.Release(); err != nil {
				cleanupErr := terminateAgentChild(child)
				return fmt.Errorf("RunAgent: failed to release process: %w", errors.Join(err, cleanupErr))
			}
			return nil
		}
		// Only terminate the process handle we started. In particular, do not call
		// /shutdown here: another concurrently starting agent may have won the
		// listener race and must be left untouched.
		cleanupErr := terminateAgentChild(child)
		return fmt.Errorf("RunAgent: agent did not become ready: %w", errors.Join(readyErr, cleanupErr))
	case <-child.Done():
		// Reap first, then let the global readiness observation decide the result.
		// A concurrently spawned winner may legitimately be serving /ready even
		// though this caller's child lost the port race and exited.
		childExitErr := child.Wait()
		readyErr := <-readyResult
		if readyErr == nil {
			return nil
		}
		if childExitErr == nil {
			childExitErr = errors.New("agent child exited before readiness")
		} else {
			childExitErr = fmt.Errorf("agent child exited before readiness: %w", childExitErr)
		}
		return fmt.Errorf("RunAgent: agent did not become ready: %w", errors.Join(readyErr, childExitErr))
	}
}

func terminateAgentChild(child agentChildProcess) error {
	killErr := child.Kill()
	waitErr := child.Wait()

	if errors.Is(killErr, os.ErrProcessDone) {
		killErr = nil
	}
	// A killed child normally reports its signal or non-zero exit through Wait;
	// that is successful reaping, not a cleanup failure.
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		waitErr = nil
	}
	if killErr != nil {
		killErr = fmt.Errorf("kill failed agent child: %w", killErr)
	}
	if waitErr != nil {
		waitErr = fmt.Errorf("wait for failed agent child: %w", waitErr)
	}
	return errors.Join(killErr, waitErr)
}

// ServeTunnelInfo starts a simple http serve that exposes the tunnel information about the running tunnel.
// The API has three endpoints:
// 1. GET    localhost:{PORT}/tunnel/{UDID} to get the tunnel info for a specific device
// 2. DELETE localhost:{PORT}/tunnel/{UDID} to stop a device tunnel
// 3. GET    localhost:{PORT}/tunnels       to get a list of all tunnels
func ServeTunnelInfo(tm *TunnelManager, port int) error {
	if err := http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", port), tunnelInfoHTTPHandler(tm)); err != nil {
		return fmt.Errorf("ServeTunnelInfo: failed to start http server: %w", err)
	}
	return nil
}

func tunnelInfoHTTPHandler(tm *TunnelManager) http.Handler {
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
			http.NotFound(writer, request)
			return
		}
		if request.Method != http.MethodGet && request.Method != http.MethodDelete {
			writer.Header().Set("Allow", "GET, DELETE")
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
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

		if request.Method == http.MethodGet {
			writer.Header().Set("Content-Type", "application/json")
			enc := json.NewEncoder(writer)
			err = enc.Encode(t)
		} else {
			err = tm.removeTunnel(t)
			if err == nil {
				writer.WriteHeader(http.StatusNoContent)
			}
		}
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
	})
	mux.HandleFunc("/tunnels", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writer.Header().Set("Allow", "GET")
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		tunnels, err := tm.ListTunnels()
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		writer.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(writer)
		err = enc.Encode(tunnels)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
	})
	return mux
}

func tunnelInfoURL(host string, port int, path string) string {
	// API callers sometimes pass an IPv6 literal in URL form ("[::1]").
	// JoinHostPort adds the brackets itself, so strip exactly one matching pair.
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	return fmt.Sprintf("http://%s%s", net.JoinHostPort(host, strconv.Itoa(port)), path)
}

func readTunnelInfoResponse(operation string, response *http.Response) ([]byte, error) {
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to read body: %w", operation, err)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		detail := strings.TrimSpace(string(body))
		if detail != "" {
			return nil, fmt.Errorf("%s: server returned %s: %s", operation, response.Status, detail)
		}
		return nil, fmt.Errorf("%s: server returned %s", operation, response.Status)
	}
	return body, nil
}

func TunnelInfoForDevice(udid string, tunnelInfoHost string, tunnelInfoPort int) (Tunnel, error) {
	c := http.Client{
		Timeout: 5 * time.Second,
	}
	res, err := c.Get(tunnelInfoURL(tunnelInfoHost, tunnelInfoPort, "/tunnel/"+url.PathEscape(udid)))
	if err != nil {
		return Tunnel{}, fmt.Errorf("TunnelInfoForDevice: failed to get tunnel info: %w", err)
	}
	defer res.Body.Close()

	body, err := readTunnelInfoResponse("TunnelInfoForDevice", res)
	if err != nil {
		return Tunnel{}, err
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
	res, err := c.Get(tunnelInfoURL(tunnelInfoHost, tunnelInfoPort, "/tunnels"))
	if err != nil {
		return nil, fmt.Errorf("ListRunningTunnels: failed to get tunnel info: %w", err)
	}
	defer res.Body.Close()

	body, err := readTunnelInfoResponse("ListRunningTunnels", res)
	if err != nil {
		return nil, err
	}
	var info []Tunnel
	err = json.Unmarshal(body, &info)
	if err != nil {
		return nil, fmt.Errorf("ListRunningTunnels: failed to parse response: %w", err)
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
	nextGeneration       uint64
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
		attachment := tunnelAttachmentFingerprintForDevice(d)
		oldTunnel, replacing := localTunnels[udid]
		if replacing && oldTunnel.attachment == attachment && oldTunnel.alive() {
			continue
		}
		if replacing {
			if !oldTunnel.alive() && oldTunnel.Err() != nil {
				log.WithFields(log.Fields{
					"udid": udid,
					"err":  oldTunnel.Err(),
				}).Warn("rebuilding stopped tunnel underlay")
			}
			// A different usbmux attachment with the same UDID is a new physical
			// generation. A stopped underlay with the same attachment is likewise
			// unusable. Remove and fully join either one before starting a replacement.
			// On a start failure the slot intentionally remains absent (not ready) and
			// the next update retries the current attachment.
			if stopErr := m.stopTunnel(oldTunnel); stopErr != nil {
				updateErr = errors.Join(updateErr, fmt.Errorf("stop replaced tunnel for %s: %w", udid, stopErr))
			}
			delete(localTunnels, udid)
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
		t.attachment = attachment
		m.mux.Lock()
		_, currentExists := m.tunnels[udid]
		canPublish := !m.closed && !currentExists
		if canPublish {
			m.nextGeneration++
			t.generation = m.nextGeneration
			localTunnels[udid] = t
			m.tunnels[udid] = t
		}
		m.mux.Unlock()
		if !canPublish {
			if closeErr := t.Close(); closeErr != nil {
				updateErr = errors.Join(updateErr, fmt.Errorf("close unpublished tunnel for %s: %w", udid, closeErr))
			}
			continue
		}
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

func tunnelAttachmentFingerprintForDevice(device ios.DeviceEntry) tunnelAttachmentFingerprint {
	return tunnelAttachmentFingerprint{
		deviceID:   device.DeviceID,
		locationID: device.Properties.LocationID,
	}
}

func (m *TunnelManager) RemoveTunnel(ctx context.Context, serialNumber string) error {
	m.updateMux.Lock()
	defer m.updateMux.Unlock()

	m.mux.RLock()
	tun, ok := m.tunnels[serialNumber]
	m.mux.RUnlock()
	if !ok {
		return errors.New("tunnel not found")
	}
	return m.stopTunnel(tun)
}

// removeTunnel serializes an already-resolved generation with UpdateTunnels
// and Close. Keeping the token avoids a delayed HTTP DELETE closing a newer
// attachment that reused the same UDID.
func (m *TunnelManager) removeTunnel(t Tunnel) error {
	m.updateMux.Lock()
	defer m.updateMux.Unlock()
	return m.stopTunnel(t)
}

func (m *TunnelManager) stopTunnel(t Tunnel) error {
	m.mux.Lock()
	current, exists := m.tunnels[t.Udid]
	if !exists || current.generation != t.generation {
		m.mux.Unlock()
		return nil
	}
	delete(m.tunnels, t.Udid)
	m.mux.Unlock()

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

	if usesCoreDeviceTunnelProtocol(version) {
		if userspaceTUN {
			tun, err := ConnectUserSpaceTunnelLockdownContext(ctx, device, device.UserspaceTUNPort)
			tun.UserspaceTUN = true
			tun.UserspaceTUNPort = device.UserspaceTUNPort
			return tun, err
		}
		return ConnectTunnelLockdownContext(ctx, device)
	}
	if version.Major() >= 17 {
		if userspaceTUN {
			return Tunnel{}, errors.New("manualPairingTunnelStart: userspaceTUN not supported for iOS >=17 and < 17.4")
		}
		return ManualPairAndConnectToTunnel(ctx, device, p)
	}
	return Tunnel{}, fmt.Errorf("manualPairingTunnelStart: unsupported iOS version %s", version.String())
}

func usesCoreDeviceTunnelProtocol(version *semver.Version) bool {
	return version != nil && !version.LessThan(semver.MustParse("17.4.0"))
}

type deviceList struct {
}

func (d deviceList) ListDevices() (ios.DeviceList, error) {
	return ios.ListDevices()
}
