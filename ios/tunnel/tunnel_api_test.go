package tunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Masterminds/semver"
	"github.com/danielpaulus/go-ios/ios"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func tunnelAPIEndpoint(t *testing.T, server *httptest.Server) (string, int) {
	t.Helper()
	host, portString, err := net.SplitHostPort(server.Listener.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portString)
	require.NoError(t, err)
	return host, port
}

type agentRoundTripFunc func(*http.Request) (*http.Response, error)

func (f agentRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type trackedAgentResponseBody struct {
	mu       sync.Mutex
	reader   *bytes.Reader
	wantRead int
	read     int
	closed   bool
}

func newTrackedAgentResponseBody(content string) *trackedAgentResponseBody {
	return &trackedAgentResponseBody{reader: bytes.NewReader([]byte(content)), wantRead: len(content)}
}

func (b *trackedAgentResponseBody) Read(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n, err := b.reader.Read(data)
	b.read += n
	return n, err
}

func (b *trackedAgentResponseBody) Close() error {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	return nil
}

func (b *trackedAgentResponseBody) state() (fullyRead, closed bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.read == b.wantRead, b.closed
}

func agentTestResponse(request *http.Request, statusCode int, body *trackedAgentResponseBody) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
		Body:       body,
		Request:    request,
	}
}

func useAgentNetClient(t *testing.T, client *http.Client) {
	t.Helper()
	original := netClient
	netClient = client
	t.Cleanup(func() { netClient = original })
}

func assertAgentBodyDrainedAndClosed(t *testing.T, body *trackedAgentResponseBody) {
	t.Helper()
	fullyRead, closed := body.state()
	if !fullyRead || !closed {
		t.Fatalf("response body fullyRead/closed = %v/%v, want true/true", fullyRead, closed)
	}
}

func TestAgentHealthAndShutdownDrainAndCloseResponseBodies(t *testing.T) {
	t.Run("health", func(t *testing.T) {
		body := newTrackedAgentResponseBody("healthy response body")
		client := &http.Client{Transport: agentRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.Path != "/health" {
				t.Fatalf("path = %q, want /health", request.URL.Path)
			}
			return agentTestResponse(request, http.StatusOK, body), nil
		})}
		useAgentNetClient(t, client)
		if !IsAgentRunning() {
			t.Fatal("healthy agent was reported as stopped")
		}
		assertAgentBodyDrainedAndClosed(t, body)
	})

	t.Run("shutdown", func(t *testing.T) {
		body := newTrackedAgentResponseBody("shutdown response body")
		client := &http.Client{Transport: agentRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.Path != "/shutdown" {
				t.Fatalf("path = %q, want /shutdown", request.URL.Path)
			}
			return agentTestResponse(request, http.StatusOK, body), nil
		})}
		useAgentNetClient(t, client)
		if err := CloseAgent(); err != nil {
			t.Fatal(err)
		}
		assertAgentBodyDrainedAndClosed(t, body)
	})
}

func TestWaitUntilAgentReadyRetries503ThenSucceedsAndClosesBodies(t *testing.T) {
	var calls atomic.Int64
	var bodiesMu sync.Mutex
	var bodies []*trackedAgentResponseBody
	client := &http.Client{Transport: agentRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := newTrackedAgentResponseBody("readiness response body")
		bodiesMu.Lock()
		bodies = append(bodies, body)
		bodiesMu.Unlock()
		status := http.StatusServiceUnavailable
		if calls.Add(1) == 3 {
			status = http.StatusOK
		}
		return agentTestResponse(request, status, body), nil
	})}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitUntilAgentReady(ctx, client, "http://agent.test/ready", time.Millisecond, 4*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, int64(3), calls.Load())
	bodiesMu.Lock()
	gotBodies := append([]*trackedAgentResponseBody(nil), bodies...)
	bodiesMu.Unlock()
	for _, body := range gotBodies {
		assertAgentBodyDrainedAndClosed(t, body)
	}
}

func TestWaitUntilAgentReadyPermanent503TimesOutWithBoundedBackoff(t *testing.T) {
	var calls atomic.Int64
	client := &http.Client{Transport: agentRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		return agentTestResponse(request, http.StatusServiceUnavailable, newTrackedAgentResponseBody("not ready")), nil
	})}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err := waitUntilAgentReady(ctx, client, "http://agent.test/ready", time.Millisecond, 4*time.Millisecond)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Contains(t, err.Error(), "HTTP status 503")
	if got := calls.Load(); got < 2 || got > 20 {
		t.Fatalf("readiness requests = %d, want bounded retries", got)
	}
}

func TestWaitUntilAgentReadyTransportErrorIsReturnedAtDeadline(t *testing.T) {
	wantErr := errors.New("transport failed")
	var calls atomic.Int64
	client := &http.Client{Transport: agentRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, wantErr
	})}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := waitUntilAgentReady(ctx, client, "http://agent.test/ready", time.Millisecond, 4*time.Millisecond)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.ErrorIs(t, err, wantErr)
	if got := calls.Load(); got < 2 || got > 20 {
		t.Fatalf("readiness requests = %d, want bounded retries", got)
	}
}

type fakeAgentChildProcess struct {
	releaseCalls int
	killCalls    int
	waitCalls    int
	releaseErr   error
	killErr      error
	waitErr      error
	done         <-chan struct{}
	onWait       func()
}

func (p *fakeAgentChildProcess) Release() error {
	p.releaseCalls++
	return p.releaseErr
}

func (p *fakeAgentChildProcess) Kill() error {
	p.killCalls++
	return p.killErr
}

func (p *fakeAgentChildProcess) Wait() error {
	p.waitCalls++
	if p.onWait != nil {
		p.onWait()
	}
	return p.waitErr
}

func (p *fakeAgentChildProcess) Done() <-chan struct{} {
	return p.done
}

func TestRunAgentExistingHealthyAgentStillWaitsUntilReady(t *testing.T) {
	var readyCalls atomic.Int64
	client := &http.Client{Transport: agentRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		status := http.StatusServiceUnavailable
		if readyCalls.Add(1) == 3 {
			status = http.StatusOK
		}
		return agentTestResponse(request, status, newTrackedAgentResponseBody("ready")), nil
	})}
	startCalled := false
	operations := runAgentOperations{
		isRunning: func(context.Context) (bool, error) { return true, nil },
		waitReady: func(ctx context.Context) error {
			return waitUntilAgentReady(ctx, client, "http://agent.test/ready", time.Millisecond, 4*time.Millisecond)
		},
		executable: func() (string, error) { return "/unused", nil },
		start: func(string, []string) (agentChildProcess, error) {
			startCalled = true
			return nil, errors.New("must not start")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, runAgent(ctx, "user", nil, operations))
	assert.Equal(t, int64(3), readyCalls.Load())
	assert.False(t, startCalled)
}

func TestRunAgentExistingHealthyButPermanentlyUnreadyReturnsTimeout(t *testing.T) {
	var readyCalls atomic.Int64
	client := &http.Client{Transport: agentRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		readyCalls.Add(1)
		return agentTestResponse(request, http.StatusServiceUnavailable, newTrackedAgentResponseBody("not ready")), nil
	})}
	operations := runAgentOperations{
		isRunning: func(context.Context) (bool, error) { return true, nil },
		waitReady: func(ctx context.Context) error {
			return waitUntilAgentReady(ctx, client, "http://agent.test/ready", time.Millisecond, 4*time.Millisecond)
		},
		executable: func() (string, error) { return "/unused", nil },
		start: func(string, []string) (agentChildProcess, error) {
			t.Fatal("must not start a second process for a live agent")
			return nil, nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err := runAgent(ctx, "user", nil, operations)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Contains(t, err.Error(), "existing agent did not become ready")
	assert.GreaterOrEqual(t, readyCalls.Load(), int64(2))
}

func TestRunAgentReadinessFailureKillsAndWaitsForStartedChild(t *testing.T) {
	wantReadyErr := errors.New("readiness failed")
	child := &fakeAgentChildProcess{}
	operations := runAgentOperations{
		isRunning:  func(context.Context) (bool, error) { return false, errors.New("connection refused") },
		waitReady:  func(context.Context) error { return wantReadyErr },
		executable: func() (string, error) { return "/test/go-ios", nil },
		start: func(executable string, arguments []string) (agentChildProcess, error) {
			assert.Equal(t, "/test/go-ios", executable)
			assert.Equal(t, []string{"tunnel", "start", "--userspace", "--pair-record-path=/records"}, arguments)
			return child, nil
		},
	}

	err := runAgent(context.Background(), "user", []string{"--pair-record-path=/records"}, operations)
	require.Error(t, err)
	assert.ErrorIs(t, err, wantReadyErr)
	assert.Equal(t, 0, child.releaseCalls)
	assert.Equal(t, 1, child.killCalls)
	assert.Equal(t, 1, child.waitCalls)
}

func TestRunAgentReapsExitedLoserAndAcceptsConcurrentWinnerReadiness(t *testing.T) {
	childDone := make(chan struct{})
	close(childDone)
	waitObserved := make(chan struct{})
	globalReady := make(chan struct{})
	var signalWait sync.Once
	child := &fakeAgentChildProcess{
		done:    childDone,
		waitErr: errors.New("listen address already in use"),
		onWait: func() {
			signalWait.Do(func() { close(waitObserved) })
		},
	}
	go func() {
		<-waitObserved
		close(globalReady)
	}()
	operations := runAgentOperations{
		isRunning: func(context.Context) (bool, error) { return false, errors.New("connection refused") },
		waitReady: func(context.Context) error {
			<-globalReady
			return nil
		},
		executable: func() (string, error) { return "/test/go-ios", nil },
		start:      func(string, []string) (agentChildProcess, error) { return child, nil },
	}

	require.NoError(t, runAgent(context.Background(), "kernel", nil, operations))
	assert.Equal(t, 0, child.releaseCalls)
	assert.Equal(t, 0, child.killCalls, "must not kill a different process that won readiness")
	assert.Equal(t, 1, child.waitCalls)
}

func TestNewAgentCommandRemovesAutoStartEnvironment(t *testing.T) {
	t.Setenv(agentAutoStartEnvironment, "user")
	command := newAgentCommand("/test/go-ios", []string{"tunnel", "start", "--userspace"})
	assert.Equal(t, []string{"/test/go-ios", "tunnel", "start", "--userspace"}, command.Args)
	for _, entry := range command.Env {
		key, _, found := strings.Cut(entry, "=")
		if found && strings.EqualFold(key, agentAutoStartEnvironment) {
			t.Fatalf("child command inherited %s: %q", agentAutoStartEnvironment, entry)
		}
	}
}

func TestTunnelInfoURLNormalizesIPv6Literal(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{name: "IPv4", host: "127.0.0.1", want: "http://127.0.0.1:60105/tunnels"},
		{name: "IPv6", host: "::1", want: "http://[::1]:60105/tunnels"},
		{name: "bracketed IPv6", host: "[::1]", want: "http://[::1]:60105/tunnels"},
		{name: "bracketed IPv6 zone", host: "[fe80::1%lo0]", want: "http://[fe80::1%lo0]:60105/tunnels"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, tunnelInfoURL(test.host, 60105, "/tunnels"))
		})
	}
}

func TestTunnelInfoForDeviceRoundTripUsesObjectContract(t *testing.T) {
	manager := NewTunnelManager(PairRecordManager{}, true)
	want := Tunnel{
		Address:          "fd00::1",
		RsdPort:          62078,
		Udid:             "device-object-contract",
		UserspaceTUN:     true,
		UserspaceTUNPort: 60106,
	}
	manager.tunnels[want.Udid] = want
	server := httptest.NewServer(tunnelInfoHTTPHandler(manager))
	defer server.Close()
	host, port := tunnelAPIEndpoint(t, server)

	got, err := TunnelInfoForDevice(want.Udid, host, port)
	require.NoError(t, err)
	assert.Equal(t, want.Address, got.Address)
	assert.Equal(t, want.RsdPort, got.RsdPort)
	assert.Equal(t, want.Udid, got.Udid)
	assert.Equal(t, want.UserspaceTUN, got.UserspaceTUN)
	assert.Equal(t, want.UserspaceTUNPort, got.UserspaceTUNPort)

	response, err := http.Get(server.URL + "/tunnel/" + want.Udid)
	require.NoError(t, err)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, "application/json", response.Header.Get("Content-Type"))
	trimmed := bytes.TrimSpace(body)
	require.NotEmpty(t, trimmed)
	assert.Equal(t, byte('{'), trimmed[0], "single-device endpoint must return a JSON object")
	var decoded Tunnel
	require.NoError(t, json.Unmarshal(trimmed, &decoded))
	assert.Equal(t, want.Udid, decoded.Udid)
}

func TestTunnelInfoForDeviceRejectsNon2xxWithValidTunnelJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(writer).Encode(Tunnel{Udid: "must-not-be-accepted"})
	}))
	defer server.Close()
	host, port := tunnelAPIEndpoint(t, server)

	got, err := TunnelInfoForDevice("device", host, port)
	assert.Equal(t, Tunnel{}, got)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "503 Service Unavailable")
	assert.Contains(t, err.Error(), "must-not-be-accepted")
}

func TestListRunningTunnelsRejectsNon2xxWithValidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusBadGateway)
		_, _ = writer.Write([]byte("[]"))
	}))
	defer server.Close()
	host, port := tunnelAPIEndpoint(t, server)

	got, err := ListRunningTunnels(host, port)
	assert.Nil(t, got)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "502 Bad Gateway")
}

func TestTunnelInfoDeleteRoundTripStopsAndRemovesTunnel(t *testing.T) {
	manager := NewTunnelManager(PairRecordManager{}, true)
	var closeCalls atomic.Int64
	const udid = "device-delete-contract"
	manager.tunnels[udid] = Tunnel{
		Udid: udid,
		closer: func() error {
			closeCalls.Add(1)
			return nil
		},
	}
	server := httptest.NewServer(tunnelInfoHTTPHandler(manager))
	defer server.Close()

	request, err := http.NewRequest(http.MethodDelete, server.URL+"/tunnel/"+udid, nil)
	require.NoError(t, err)
	response, err := server.Client().Do(request)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, http.StatusNoContent, response.StatusCode)
	assert.Empty(t, body)
	assert.Equal(t, int64(1), closeCalls.Load())

	got, err := manager.FindTunnel(udid)
	require.NoError(t, err)
	assert.Empty(t, got.Udid)

	request, err = http.NewRequest(http.MethodDelete, server.URL+"/tunnel/"+udid, nil)
	require.NoError(t, err)
	response, err = server.Client().Do(request)
	require.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, http.StatusNotFound, response.StatusCode)
	assert.Equal(t, int64(1), closeCalls.Load())
}

func TestTunnelInfoDeleteSerializesBlockingCloseWithManagerOperations(t *testing.T) {
	for _, test := range []struct {
		name       string
		concurrent func(*TunnelManager) error
	}{
		{name: "manager close", concurrent: func(manager *TunnelManager) error { return manager.Close() }},
		{name: "manager update", concurrent: func(manager *TunnelManager) error {
			manager.dl = staticDeviceLister{}
			return manager.UpdateTunnels(context.Background())
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := NewTunnelManager(PairRecordManager{}, false)
			closeStarted := make(chan struct{})
			releaseClose := make(chan struct{})
			var closeCalls atomic.Int64
			const udid = "blocking-delete"
			manager.tunnels[udid] = Tunnel{
				Udid:       udid,
				generation: 1,
				closer: func() error {
					closeCalls.Add(1)
					close(closeStarted)
					<-releaseClose
					return nil
				},
			}
			server := httptest.NewServer(tunnelInfoHTTPHandler(manager))
			defer server.Close()

			deleteResult := make(chan error, 1)
			go func() {
				request, err := http.NewRequest(http.MethodDelete, server.URL+"/tunnel/"+udid, nil)
				if err != nil {
					deleteResult <- err
					return
				}
				response, err := server.Client().Do(request)
				if err == nil {
					_ = response.Body.Close()
					if response.StatusCode != http.StatusNoContent {
						err = fmt.Errorf("DELETE status = %d, want %d", response.StatusCode, http.StatusNoContent)
					}
				}
				deleteResult <- err
			}()
			<-closeStarted

			concurrentResult := make(chan error, 1)
			go func() { concurrentResult <- test.concurrent(manager) }()
			select {
			case err := <-concurrentResult:
				t.Fatalf("%s returned before DELETE close joined: %v", test.name, err)
			case <-time.After(20 * time.Millisecond):
			}
			close(releaseClose)
			require.NoError(t, <-deleteResult)
			require.NoError(t, <-concurrentResult)
			assert.Equal(t, int64(1), closeCalls.Load())
		})
	}
}

func TestTunnelInfoDeleteFailureDoesNotRepublishStoppedHandle(t *testing.T) {
	manager := NewTunnelManager(PairRecordManager{}, true)
	var closeCalls atomic.Int64
	wantErr := errors.New("close failed")
	const udid = "device-delete-failure"
	manager.tunnels[udid] = Tunnel{
		Udid:       udid,
		generation: 1,
		closer: func() error {
			closeCalls.Add(1)
			return wantErr
		},
	}
	server := httptest.NewServer(tunnelInfoHTTPHandler(manager))
	defer server.Close()

	request, err := http.NewRequest(http.MethodDelete, server.URL+"/tunnel/"+udid, nil)
	require.NoError(t, err)
	response, err := server.Client().Do(request)
	require.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, response.StatusCode)
	assert.Equal(t, int64(1), closeCalls.Load())
	removed, err := manager.FindTunnel(udid)
	require.NoError(t, err)
	assert.Empty(t, removed.Udid)

	request, err = http.NewRequest(http.MethodDelete, server.URL+"/tunnel/"+udid, nil)
	require.NoError(t, err)
	response, err = server.Client().Do(request)
	require.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, http.StatusNotFound, response.StatusCode)
	assert.Equal(t, int64(1), closeCalls.Load())
}

func TestTunnelInfoEndpointRejectsUnsupportedMethod(t *testing.T) {
	manager := NewTunnelManager(PairRecordManager{}, false)
	manager.tunnels["device"] = Tunnel{Udid: "device"}
	server := httptest.NewServer(tunnelInfoHTTPHandler(manager))
	defer server.Close()

	request, err := http.NewRequest(http.MethodPost, server.URL+"/tunnel/device", nil)
	require.NoError(t, err)
	response, err := server.Client().Do(request)
	require.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, response.StatusCode)
	assert.Equal(t, "GET, DELETE", response.Header.Get("Allow"))
}

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

func TestTunnelManagerAssignsNewGenerationOnRepublish(t *testing.T) {
	device := ios.DeviceEntry{Properties: ios.DeviceProperties{SerialNumber: "device"}}
	manager := NewTunnelManager(PairRecordManager{}, false)
	manager.getProductVersion = func(ios.DeviceEntry) (*semver.Version, error) {
		return semver.MustParse("17.5.0"), nil
	}
	manager.ts = tunnelStarterFunc(func(context.Context, ios.DeviceEntry, PairRecordManager, *semver.Version, bool) (Tunnel, error) {
		return Tunnel{closer: func() error { return nil }}, nil
	})

	manager.dl = staticDeviceLister{devices: ios.DeviceList{DeviceList: []ios.DeviceEntry{device}}}
	require.NoError(t, manager.UpdateTunnels(context.Background()))
	first, err := manager.FindTunnel("device")
	require.NoError(t, err)
	require.NotZero(t, first.generation)

	manager.dl = staticDeviceLister{}
	require.NoError(t, manager.UpdateTunnels(context.Background()))
	manager.dl = staticDeviceLister{devices: ios.DeviceList{DeviceList: []ios.DeviceEntry{device}}}
	require.NoError(t, manager.UpdateTunnels(context.Background()))
	second, err := manager.FindTunnel("device")
	require.NoError(t, err)
	assert.Greater(t, second.generation, first.generation)
}

func TestTunnelManagerStopsChangedAttachmentBeforeStartingReplacement(t *testing.T) {
	const udid = "same-udid"
	oldDevice := ios.DeviceEntry{DeviceID: 101, Properties: ios.DeviceProperties{SerialNumber: udid, LocationID: 11}}
	newDevice := ios.DeviceEntry{DeviceID: 202, Properties: ios.DeviceProperties{SerialNumber: udid, LocationID: 11}}
	manager := NewTunnelManager(PairRecordManager{}, false)
	manager.getProductVersion = func(ios.DeviceEntry) (*semver.Version, error) {
		return semver.MustParse("17.5.0"), nil
	}
	var oldClosed atomic.Bool
	manager.ts = tunnelStarterFunc(func(_ context.Context, device ios.DeviceEntry, _ PairRecordManager, _ *semver.Version, _ bool) (Tunnel, error) {
		switch device.DeviceID {
		case oldDevice.DeviceID:
			return Tunnel{Address: "old", closer: func() error { oldClosed.Store(true); return nil }}, nil
		case newDevice.DeviceID:
			if !oldClosed.Load() {
				t.Fatal("replacement starter ran before the old attachment finished closing")
			}
			return Tunnel{Address: "new", closer: func() error { return nil }}, nil
		default:
			return Tunnel{}, fmt.Errorf("unexpected DeviceID %d", device.DeviceID)
		}
	})

	manager.dl = staticDeviceLister{devices: ios.DeviceList{DeviceList: []ios.DeviceEntry{oldDevice}}}
	require.NoError(t, manager.UpdateTunnels(context.Background()))
	oldTunnel, err := manager.FindTunnel(udid)
	require.NoError(t, err)
	require.Equal(t, "old", oldTunnel.Address)

	manager.dl = staticDeviceLister{devices: ios.DeviceList{DeviceList: []ios.DeviceEntry{newDevice}}}
	require.NoError(t, manager.UpdateTunnels(context.Background()))
	current, err := manager.FindTunnel(udid)
	require.NoError(t, err)
	assert.Equal(t, "new", current.Address)
	assert.Greater(t, current.generation, oldTunnel.generation)
	assert.Equal(t, tunnelAttachmentFingerprintForDevice(newDevice), current.attachment)
	assert.True(t, oldClosed.Load())
}

func TestTunnelManagerChangedAttachmentStartFailureLeavesNoStaleRecordAndRetries(t *testing.T) {
	const udid = "same-udid-retry"
	oldDevice := ios.DeviceEntry{DeviceID: 301, Properties: ios.DeviceProperties{SerialNumber: udid, LocationID: 21}}
	newDevice := ios.DeviceEntry{DeviceID: 302, Properties: ios.DeviceProperties{SerialNumber: udid, LocationID: 21}}
	wantErr := errors.New("replacement start failed")
	manager := NewTunnelManager(PairRecordManager{}, false)
	manager.getProductVersion = func(ios.DeviceEntry) (*semver.Version, error) {
		return semver.MustParse("17.5.0"), nil
	}
	var replacementAttempts atomic.Int64
	var oldCloseCalls atomic.Int64
	manager.ts = tunnelStarterFunc(func(_ context.Context, device ios.DeviceEntry, _ PairRecordManager, _ *semver.Version, _ bool) (Tunnel, error) {
		if device.DeviceID == oldDevice.DeviceID {
			return Tunnel{Address: "old", closer: func() error { oldCloseCalls.Add(1); return nil }}, nil
		}
		if replacementAttempts.Add(1) == 1 {
			return Tunnel{}, wantErr
		}
		return Tunnel{Address: "replacement", closer: func() error { return nil }}, nil
	})

	manager.dl = staticDeviceLister{devices: ios.DeviceList{DeviceList: []ios.DeviceEntry{oldDevice}}}
	require.NoError(t, manager.UpdateTunnels(context.Background()))
	manager.dl = staticDeviceLister{devices: ios.DeviceList{DeviceList: []ios.DeviceEntry{newDevice}}}
	assert.ErrorIs(t, manager.UpdateTunnels(context.Background()), wantErr)
	missing, err := manager.FindTunnel(udid)
	require.NoError(t, err)
	assert.Empty(t, missing.Udid, "failed replacement must not expose the old attachment endpoint")
	assert.Equal(t, int64(1), oldCloseCalls.Load())

	require.NoError(t, manager.UpdateTunnels(context.Background()))
	current, err := manager.FindTunnel(udid)
	require.NoError(t, err)
	assert.Equal(t, "replacement", current.Address)
	assert.Equal(t, int64(2), replacementAttempts.Load())
}

func TestTunnelAttachmentFingerprintIncludesLocationID(t *testing.T) {
	first := ios.DeviceEntry{DeviceID: 7, Properties: ios.DeviceProperties{LocationID: 100}}
	second := first
	second.Properties.LocationID = 101
	assert.NotEqual(t, tunnelAttachmentFingerprintForDevice(first), tunnelAttachmentFingerprintForDevice(second))
}

func TestUsesCoreDeviceTunnelProtocolVersionBoundary(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{version: "17.3.9", want: false},
		{version: "17.4.0", want: true},
		{version: "17.4.1", want: true},
	}
	for _, test := range tests {
		t.Run(test.version, func(t *testing.T) {
			assert.Equal(t, test.want, usesCoreDeviceTunnelProtocol(semver.MustParse(test.version)))
		})
	}
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

func TestStopTunnelIgnoresStaleGeneration(t *testing.T) {
	manager := NewTunnelManager(PairRecordManager{}, false)
	var staleCloseCalls atomic.Int64
	var currentCloseCalls atomic.Int64
	stale := Tunnel{
		Udid:       "device",
		generation: 1,
		closer:     func() error { staleCloseCalls.Add(1); return nil },
	}
	current := Tunnel{
		Udid:       "device",
		generation: 2,
		closer:     func() error { currentCloseCalls.Add(1); return nil },
	}
	manager.tunnels["device"] = current

	require.NoError(t, manager.stopTunnel(stale))
	assert.Zero(t, staleCloseCalls.Load())
	assert.Zero(t, currentCloseCalls.Load())
	preserved, err := manager.FindTunnel("device")
	require.NoError(t, err)
	assert.Equal(t, current.generation, preserved.generation)
}

func TestStopTunnelCloseFailureDoesNotOverwriteReplacement(t *testing.T) {
	manager := NewTunnelManager(PairRecordManager{}, false)
	closeStarted := make(chan struct{})
	releaseClose := make(chan struct{})
	wantErr := errors.New("old close failed")
	old := Tunnel{
		Udid:       "device",
		generation: 1,
		closer: func() error {
			close(closeStarted)
			<-releaseClose
			return wantErr
		},
	}
	replacement := Tunnel{
		Udid:       "device",
		generation: 2,
		closer:     func() error { return nil },
	}
	manager.tunnels["device"] = old

	stopResult := make(chan error, 1)
	go func() { stopResult <- manager.stopTunnel(old) }()
	<-closeStarted
	manager.mux.Lock()
	manager.tunnels["device"] = replacement
	manager.mux.Unlock()
	close(releaseClose)
	require.ErrorIs(t, <-stopResult, wantErr)

	current, err := manager.FindTunnel("device")
	require.NoError(t, err)
	assert.Equal(t, replacement.generation, current.generation)
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
