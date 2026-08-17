package ios

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type userSpaceTUNTestConn struct {
	mu sync.Mutex

	written        bytes.Buffer
	writeLimit     int
	writeError     error
	writeErrorCall int
	zeroWriteCall  int
	writeCalls     int
	closeCalls     int
	keepAliveError error
	keepPeriodErr  error
}

func (c *userSpaceTUNTestConn) Read([]byte) (int, error) { return 0, io.EOF }

func (c *userSpaceTUNTestConn) Write(data []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeCalls++
	if c.writeCalls == c.zeroWriteCall {
		return 0, nil
	}
	count := len(data)
	if c.writeLimit > 0 && count > c.writeLimit {
		count = c.writeLimit
	}
	if c.writeError != nil && c.writeCalls == c.writeErrorCall && count > 1 {
		count--
	}
	_, _ = c.written.Write(data[:count])
	if c.writeError != nil && c.writeCalls == c.writeErrorCall {
		return count, c.writeError
	}
	return count, nil
}

func (c *userSpaceTUNTestConn) Close() error {
	c.mu.Lock()
	c.closeCalls++
	c.mu.Unlock()
	return nil
}

func (c *userSpaceTUNTestConn) LocalAddr() net.Addr              { return userSpaceTUNTestAddr("local") }
func (c *userSpaceTUNTestConn) RemoteAddr() net.Addr             { return userSpaceTUNTestAddr("remote") }
func (c *userSpaceTUNTestConn) SetDeadline(time.Time) error      { return nil }
func (c *userSpaceTUNTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *userSpaceTUNTestConn) SetWriteDeadline(time.Time) error { return nil }
func (c *userSpaceTUNTestConn) SetKeepAlive(bool) error          { return c.keepAliveError }
func (c *userSpaceTUNTestConn) SetKeepAlivePeriod(time.Duration) error {
	return c.keepPeriodErr
}

func (c *userSpaceTUNTestConn) state() ([]byte, int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.written.Bytes()...), c.writeCalls, c.closeCalls
}

type userSpaceTUNTestAddr string

func (a userSpaceTUNTestAddr) Network() string { return "test" }
func (a userSpaceTUNTestAddr) String() string  { return string(a) }

func userSpaceTUNTestDevice() DeviceEntry {
	return DeviceEntry{
		UserspaceTUN:     true,
		UserspaceTUNHost: "127.0.0.1",
		UserspaceTUNPort: 60106,
	}
}

func userSpaceTUNExpectedHeader(t *testing.T, address string, port int) []byte {
	t.Helper()
	ip := net.ParseIP(address).To16()
	if ip == nil {
		t.Fatalf("invalid fixture IP %q", address)
	}
	header := make([]byte, net.IPv6len+4)
	copy(header, ip)
	binary.LittleEndian.PutUint32(header[net.IPv6len:], uint32(port))
	return header
}

func userSpaceTUNSuccessfulResolver(t *testing.T) userSpaceTUNAddressResolver {
	t.Helper()
	return func(network, address string) (*net.TCPAddr, error) {
		if network != "tcp4" {
			t.Fatalf("resolve network = %q, want tcp4", network)
		}
		if address != "127.0.0.1:60106" {
			t.Fatalf("resolve address = %q, want 127.0.0.1:60106", address)
		}
		return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 60106}, nil
	}
}

func TestConnectUserSpaceTUNDeviceWritesCompleteHeaderAcrossShortWrites(t *testing.T) {
	conn := &userSpaceTUNTestConn{writeLimit: 3}
	resolved := userSpaceTUNSuccessfulResolver(t)
	got, err := connectUserSpaceTUNDevice("fd00::44", 62078, userSpaceTUNTestDevice(), resolved, func(network string, localAddr, remoteAddr *net.TCPAddr) (userSpaceTUNClientConn, error) {
		if network != "tcp" || localAddr != nil || remoteAddr.Port != 60106 {
			t.Fatalf("dial arguments = %q, %v, %v", network, localAddr, remoteAddr)
		}
		return conn, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != conn {
		t.Fatal("connectUserSpaceTUNDevice returned a different connection")
	}
	written, calls, closes := conn.state()
	if calls <= 1 {
		t.Fatalf("Write() calls = %d, want multiple short writes", calls)
	}
	if want := userSpaceTUNExpectedHeader(t, "fd00::44", 62078); !bytes.Equal(written, want) {
		t.Fatalf("destination header = %x, want %x", written, want)
	}
	if len(written) != 20 {
		t.Fatalf("destination header length = %d, want 20", len(written))
	}
	if closes != 0 {
		t.Fatalf("successful connection Close() calls = %d, want 0", closes)
	}
	_ = got.Close()
}

func TestConnectTUNDeviceUserspaceRoundTripWritesTwentyByteHeader(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := listener.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	headerResult := make(chan struct {
		header []byte
		err    error
	}, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			headerResult <- struct {
				header []byte
				err    error
			}{err: err}
			return
		}
		defer conn.Close()
		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			headerResult <- struct {
				header []byte
				err    error
			}{err: err}
			return
		}
		header := make([]byte, 20)
		_, err = io.ReadFull(conn, header)
		headerResult <- struct {
			header []byte
			err    error
		}{header: header, err: err}
	}()

	device := userSpaceTUNTestDevice()
	device.UserspaceTUNPort = listener.Addr().(*net.TCPAddr).Port
	conn, err := ConnectTUNDevice("fd00::88", 62078, device)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	select {
	case result := <-headerResult:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if want := userSpaceTUNExpectedHeader(t, "fd00::88", 62078); !bytes.Equal(result.header, want) {
			t.Fatalf("destination header = %x, want %x", result.header, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for userspace TUN destination header")
	}
}

func TestConnectUserSpaceTUNDeviceClosesOnHeaderWriteFailure(t *testing.T) {
	tests := []struct {
		name string
		conn *userSpaceTUNTestConn
		err  error
	}{
		{
			name: "partial write error",
			conn: &userSpaceTUNTestConn{writeLimit: 7, writeError: errors.New("write failed"), writeErrorCall: 2},
		},
		{
			name: "zero progress",
			conn: &userSpaceTUNTestConn{zeroWriteCall: 1},
			err:  io.ErrNoProgress,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := connectUserSpaceTUNDevice("fd00::55", 62078, userSpaceTUNTestDevice(), userSpaceTUNSuccessfulResolver(t), func(string, *net.TCPAddr, *net.TCPAddr) (userSpaceTUNClientConn, error) {
				return test.conn, nil
			})
			if got != nil {
				t.Fatal("failed header write returned a connection")
			}
			wantErr := test.err
			if wantErr == nil {
				wantErr = test.conn.writeError
			}
			if !errors.Is(err, wantErr) {
				t.Fatalf("error = %v, want %v", err, wantErr)
			}
			_, _, closes := test.conn.state()
			if closes != 1 {
				t.Fatalf("failed connection Close() calls = %d, want 1", closes)
			}
		})
	}
}

func TestConnectUserSpaceTUNDeviceClosesOnKeepaliveFailure(t *testing.T) {
	tests := []struct {
		name string
		conn *userSpaceTUNTestConn
		err  error
	}{
		{
			name: "enable keepalive",
			err:  errors.New("keepalive failed"),
		},
		{
			name: "set keepalive period",
			err:  errors.New("keepalive period failed"),
		},
	}
	tests[0].conn = &userSpaceTUNTestConn{keepAliveError: tests[0].err}
	tests[1].conn = &userSpaceTUNTestConn{keepPeriodErr: tests[1].err}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := connectUserSpaceTUNDevice("fd00::66", 62078, userSpaceTUNTestDevice(), userSpaceTUNSuccessfulResolver(t), func(string, *net.TCPAddr, *net.TCPAddr) (userSpaceTUNClientConn, error) {
				return test.conn, nil
			})
			if got != nil || !errors.Is(err, test.err) {
				t.Fatalf("result = %v, %v, want nil and %v", got, err, test.err)
			}
			written, _, closes := test.conn.state()
			if len(written) != 0 {
				t.Fatalf("keepalive failure wrote %d header bytes", len(written))
			}
			if closes != 1 {
				t.Fatalf("failed connection Close() calls = %d, want 1", closes)
			}
		})
	}
}

func TestConnectUserSpaceTUNDevicePropagatesResolveFailureWithoutDial(t *testing.T) {
	wantErr := errors.New("resolve failed")
	dialed := false
	got, err := connectUserSpaceTUNDevice("fd00::77", 62078, userSpaceTUNTestDevice(), func(network, address string) (*net.TCPAddr, error) {
		return nil, wantErr
	}, func(string, *net.TCPAddr, *net.TCPAddr) (userSpaceTUNClientConn, error) {
		dialed = true
		return &userSpaceTUNTestConn{}, nil
	})
	if got != nil || !errors.Is(err, wantErr) {
		t.Fatalf("result = %v, %v, want nil and %v", got, err, wantErr)
	}
	if dialed {
		t.Fatal("dialer was called after address resolution failed")
	}
}

func TestConnectUserSpaceTUNDeviceRejectsInvalidDestinationBeforeDial(t *testing.T) {
	tests := []struct {
		name       string
		remoteIP   string
		remotePort int
		device     DeviceEntry
	}{
		{name: "invalid IP", remoteIP: "not-an-ip", remotePort: 62078, device: userSpaceTUNTestDevice()},
		{name: "negative remote port", remoteIP: "fd00::1", remotePort: -1, device: userSpaceTUNTestDevice()},
		{name: "oversized remote port", remoteIP: "fd00::1", remotePort: 65536, device: userSpaceTUNTestDevice()},
		{name: "invalid listener port", remoteIP: "fd00::1", remotePort: 62078, device: DeviceEntry{UserspaceTUNHost: "127.0.0.1"}},
		{name: "empty listener host", remoteIP: "fd00::1", remotePort: 62078, device: DeviceEntry{UserspaceTUNPort: 60106}},
		{name: "blank listener host", remoteIP: "fd00::1", remotePort: 62078, device: DeviceEntry{UserspaceTUNHost: " \t", UserspaceTUNPort: 60106}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolved := false
			dialed := false
			got, err := connectUserSpaceTUNDevice(test.remoteIP, test.remotePort, test.device, func(string, string) (*net.TCPAddr, error) {
				resolved = true
				return &net.TCPAddr{}, nil
			}, func(string, *net.TCPAddr, *net.TCPAddr) (userSpaceTUNClientConn, error) {
				dialed = true
				return &userSpaceTUNTestConn{}, nil
			})
			if got != nil || err == nil {
				t.Fatalf("result = %v, %v, want nil connection and error", got, err)
			}
			if resolved || dialed {
				t.Fatalf("invalid destination reached resolver=%v dialer=%v", resolved, dialed)
			}
		})
	}
}
