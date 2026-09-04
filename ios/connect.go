package ios

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/danielpaulus/go-ios/ios/http"

	"github.com/danielpaulus/go-ios/ios/xpc"
)

type connectMessage struct {
	BundleID            string
	ClientVersionString string
	MessageType         string
	ProgName            string
	LibUSBMuxVersion    uint32 `plist:"kLibUSBMuxVersion"`
	DeviceID            uint32
	PortNumber          uint16
}

func newConnectMessage(deviceID int, portNumber uint16) connectMessage {
	data := connectMessage{
		BundleID:            "go.ios.control",
		ClientVersionString: "go-usbmux-0.0.1",
		MessageType:         "Connect",
		ProgName:            "go-usbmux",
		LibUSBMuxVersion:    3,
		DeviceID:            uint32(deviceID),
		PortNumber:          portNumber,
	}
	return data
}

// Connect issues a Connect Message to UsbMuxd for the given deviceID on the given port
// enabling the newCodec for it.
// It returns an error containing the UsbMux error code should the connect fail.
func (muxConn *UsbMuxConnection) Connect(deviceID int, port uint16) error {
	msg := newConnectMessage(deviceID, Ntohs(port))
	muxConn.Send(msg)
	resp, err := muxConn.ReadMessage()
	if err != nil {
		return err
	}
	response := MuxResponsefromBytes(resp.Payload)
	if response.IsSuccessFull() {
		return nil
	}
	return fmt.Errorf("Failed connecting to service, error code:%d", response.Number)
}

// serviceConfigurations stores info about which DTX based services only execute a SSL Handshake
// and then go back to sending unencrypted data right after the handshake.
var serviceConfigurations = map[string]bool{
	"com.apple.instruments.remoteserver":                 true,
	"com.apple.accessibility.axAuditDaemon.remoteserver": true,
	"com.apple.testmanagerd.lockdown":                    true,
	"com.apple.debugserver":                              true,
}

// ConnectLockdown connects this Usbmux connection to the LockDown service that
// always runs on the device on the same port. The connect call needs the deviceID which can be
// retrieved from a DeviceList using the ListDevices function. After this function
// is done, the UsbMuxConnection cannot be used anymore because the same underlying
// network connection is used for talking to Lockdown. Sending usbmux commands would break it.
// It returns a new LockDownConnection.
func (muxConn *UsbMuxConnection) ConnectLockdown(deviceID int) (*LockDownConnection, error) {
	msg := newConnectMessage(deviceID, Lockdownport)
	err := muxConn.Send(msg)
	if err != nil {
		return &LockDownConnection{}, err
	}
	resp, err := muxConn.ReadMessage()
	if err != nil {
		return &LockDownConnection{}, err
	}
	response := MuxResponsefromBytes(resp.Payload)
	if response.IsSuccessFull() {
		return &LockDownConnection{muxConn.deviceConn, "", NewPlistCodec()}, nil
	}

	return nil, fmt.Errorf("Failed connecting to Lockdown with error code:%d", response.Number)
}

func ConnectToService(device DeviceEntry, serviceName string) (DeviceConnectionInterface, error) {
	return ConnectToServiceContext(context.Background(), device, serviceName)
}

type usbMuxConnectionContextFactory func(context.Context) (*UsbMuxConnection, error)

// ConnectToServiceContext starts a lockdown service and connects to it while
// making every blocking setup stage interruptible by ctx. The context only
// controls setup; after this function succeeds, ownership of the returned
// connection belongs to the caller.
func ConnectToServiceContext(ctx context.Context, device DeviceEntry, serviceName string) (DeviceConnectionInterface, error) {
	return connectToServiceContext(ctx, device, serviceName, NewUsbMuxConnectionSimpleContext)
}

func connectToServiceContext(ctx context.Context, device DeviceEntry, serviceName string, newMux usbMuxConnectionContextFactory) (DeviceConnectionInterface, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	startServiceResponse, pairRecord, err := startServiceAndReadPairContext(ctx, device, serviceName, newMux)
	if err != nil {
		return nil, err
	}

	muxConn, err := newMux(ctx)
	if err != nil {
		return nil, connectToServiceStageError(ctx, "dial service usbmux socket", err)
	}
	if muxConn == nil || muxConn.deviceConn == nil {
		if muxConn != nil && muxConn.deviceConn != nil {
			_ = muxConn.Close()
		}
		return nil, errors.New("ConnectToServiceContext: dial service usbmux socket: empty connection")
	}
	serviceConn := muxConn.deviceConn
	serviceRawConn := serviceConn.Conn()
	if serviceRawConn == nil {
		_ = serviceConn.Close()
		return nil, errors.New("ConnectToServiceContext: dial service usbmux socket: connection has no raw socket")
	}
	// Capture the stable raw socket before TLS can replace DeviceConnection.c.
	// Calling DeviceConnection.Close from the watcher would race that swap.
	guard := closeConnectionOnContext(ctx, serviceRawConn)
	defer func() {
		if muxConn.deviceConn != nil {
			_ = muxConn.Close()
		}
		guard.Stop()
	}()

	err = muxConn.connectWithStartServiceResponse(device.DeviceID, startServiceResponse, pairRecord)
	if err != nil {
		return nil, connectToServiceStageError(ctx, "connect service and negotiate SSL", err)
	}

	result := muxConn.ReleaseDeviceConnection()
	if !guard.Stop() || ctx.Err() != nil {
		_ = result.Close()
		return nil, connectToServiceStageError(ctx, "finish service connection", nil)
	}
	return result, nil
}

func startServiceAndReadPairContext(ctx context.Context, device DeviceEntry, serviceName string, newMux usbMuxConnectionContextFactory) (StartServiceResponse, PairRecord, error) {
	muxConn, err := newMux(ctx)
	if err != nil {
		return StartServiceResponse{}, PairRecord{}, connectToServiceStageError(ctx, "dial lockdown usbmux socket", err)
	}
	if muxConn == nil || muxConn.deviceConn == nil {
		if muxConn != nil && muxConn.deviceConn != nil {
			_ = muxConn.Close()
		}
		return StartServiceResponse{}, PairRecord{}, errors.New("ConnectToServiceContext: dial lockdown usbmux socket: empty connection")
	}
	lockdownDeviceConn := muxConn.deviceConn
	lockdownRawConn := lockdownDeviceConn.Conn()
	if lockdownRawConn == nil {
		_ = lockdownDeviceConn.Close()
		return StartServiceResponse{}, PairRecord{}, errors.New("ConnectToServiceContext: dial lockdown usbmux socket: connection has no raw socket")
	}
	// The lockdown session may install a TLS wrapper. Keep cancellation tied
	// to the immutable raw socket rather than racing DeviceConnection.c.
	guard := closeConnectionOnContext(ctx, lockdownRawConn)
	defer func() {
		_ = lockdownDeviceConn.Close()
		guard.Stop()
	}()

	pairRecord, err := muxConn.ReadPair(device.Properties.SerialNumber)
	if err != nil {
		return StartServiceResponse{}, PairRecord{}, connectToServiceStageError(ctx, "read pair record", err)
	}

	lockdownConnection, err := muxConn.ConnectLockdown(device.DeviceID)
	if err != nil {
		return StartServiceResponse{}, PairRecord{}, connectToServiceStageError(ctx, "connect lockdown", err)
	}
	muxConn.ReleaseDeviceConnection()

	if _, err := lockdownConnection.StartSession(pairRecord); err != nil {
		return StartServiceResponse{}, PairRecord{}, connectToServiceStageError(ctx, "start lockdown session and negotiate SSL", err)
	}

	response, err := lockdownConnection.StartService(serviceName)
	if err != nil {
		return StartServiceResponse{}, PairRecord{}, connectToServiceStageError(ctx, "start service", err)
	}

	// Preserve the existing graceful lockdown cleanup. If StopSession itself
	// stalls, cancellation still closes the same underlying connection.
	lockdownConnection.StopSession()
	if !guard.Stop() || ctx.Err() != nil {
		return StartServiceResponse{}, PairRecord{}, connectToServiceStageError(ctx, "finish lockdown service start", nil)
	}
	return response, pairRecord, nil
}

func connectToServiceStageError(ctx context.Context, stage string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		err = errors.Join(ctxErr, err)
	}
	if err == nil {
		err = context.Canceled
	}
	return fmt.Errorf("ConnectToServiceContext: %s: %w", stage, err)
}

// ConnectToShimService opens a new connection of the tunnel interface of the provided device
// to the provided service.
// The 'RSDCheckin' required by shim services is also executed before returning the connection to the caller
func ConnectToShimService(device DeviceEntry, service string) (DeviceConnectionInterface, error) {
	if !device.SupportsRsd() {
		return nil, fmt.Errorf("ConnectToShimService: Cannot connect to %s, missing tunnel address and RSD port.  To start the tunnel, run `ios tunnel start`", service)
	}
	port := device.Rsd.GetPort(service)
	conn, err := ConnectTUNDevice(device.Address, port, device)
	if err != nil {
		return nil, err
	}
	err = RsdCheckin(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return NewDeviceConnectionWithRWC(conn), nil
}

// ConnectToServiceTunnelIface connects to a service on an iOS17+ device using a XPC over HTTP2 connection
// It returns a new xpc.Connection
func ConnectToXpcServiceTunnelIface(device DeviceEntry, serviceName string) (*xpc.Connection, error) {
	if !device.SupportsRsd() {
		return nil, fmt.Errorf("ConnectToXpcServiceTunnelIface: Cannot connect to %s, missing tunnel address and RSD port. To start the tunnel, run `ios tunnel start`", serviceName)
	}
	port := device.Rsd.GetPort(serviceName)

	conn, err := ConnectTUNDevice(device.Address, port, device)
	if err != nil {
		return nil, fmt.Errorf("ConnectToHttp2: failed to dial: %w", err)
	}

	h, err := http.NewHttpConnection(conn)
	if err != nil {
		return nil, fmt.Errorf("ConnectToXpcServiceTunnelIface: failed to connect to http2: %w", err)
	}
	return CreateXpcConnection(h)
}

func ConnectToServiceTunnelIface(device DeviceEntry, serviceName string) (DeviceConnectionInterface, error) {
	if !device.SupportsRsd() {
		return nil, fmt.Errorf("ConnectToServiceTunnelIface: Cannot connect to %s, missing tunnel address and RSD port", serviceName)
	}
	port := device.Rsd.GetPort(serviceName)

	conn, err := ConnectTUNDevice(device.Address, port, device)
	if err != nil {
		return nil, fmt.Errorf("ConnectToServiceTunnelIface: failed to connect to tunnel: %w", err)
	}

	return NewDeviceConnectionWithRWC(conn), nil
}

const defaultXPCInitializationTimeout = 10 * time.Second

func CreateXpcConnection(h *http.HttpConnection) (*xpc.Connection, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultXPCInitializationTimeout)
	defer cancel()
	return CreateXpcConnectionContext(ctx, h)
}

// CreateXpcConnectionContext performs the RemoteXPC handshake with a bounded
// lifetime. It takes ownership of h: failures close it, while a successful
// return transfers ownership to the returned xpc.Connection. The context only
// governs initialization and cannot close an established connection later.
func CreateXpcConnectionContext(ctx context.Context, h *http.HttpConnection) (*xpc.Connection, error) {
	if h == nil {
		return nil, errors.New("CreateXpcConnection: nil HTTP connection")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		_ = h.Close()
		return nil, fmt.Errorf("CreateXpcConnection: initialization canceled before start: %w", err)
	}

	keepOpen := false
	defer func() {
		if !keepOpen {
			_ = h.Close()
		}
	}()

	// Closing h is the generic cancellation mechanism for transports that do
	// not expose deadlines. Stop and join the watcher before returning success,
	// so expiration of the setup context cannot later close the live session.
	stopWatch := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-ctx.Done():
			_ = h.Close()
		case <-stopWatch:
		}
	}()
	watchStopped := false
	stopInitializationWatch := func() {
		if watchStopped {
			return
		}
		close(stopWatch)
		<-watchDone
		watchStopped = true
	}
	defer stopInitializationWatch()

	if deadline, ok := ctx.Deadline(); ok {
		if err := h.SetDeadline(deadline); err != nil {
			return nil, xpcInitializationError(ctx, "failed to set initialization deadline", err)
		}
	}

	err := initializeXpcConnection(h)
	if err != nil {
		return nil, xpcInitializationError(ctx, "failed to initialize xpc connection", err)
	}

	stopInitializationWatch()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("CreateXpcConnection: initialization did not complete before context ended: %w", err)
	}
	if err := h.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("CreateXpcConnection: failed to clear initialization deadline: %w", err)
	}

	clientServerChannel := http.NewStreamReadWriter(h, http.ClientServer)
	serverClientChannel := http.NewStreamReadWriter(h, http.ServerClient)

	xpcConn, err := xpc.New(clientServerChannel, serverClientChannel, h)
	if err != nil {
		return nil, fmt.Errorf("CreateXpcConnection: failed to create xpc connection: %w", err)
	}

	keepOpen = true
	return xpcConn, nil
}

func xpcInitializationError(ctx context.Context, stage string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("CreateXpcConnection: %s: %w", stage, ctxErr)
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return fmt.Errorf("CreateXpcConnection: %s: %w", stage, context.DeadlineExceeded)
	}
	return fmt.Errorf("CreateXpcConnection: %s: %w", stage, err)
}

// connectWithStartServiceResponse issues a Connect Message to UsbMuxd for the given deviceID on the given port
// enabling the newCodec for it. It also enables SSL on the new service connection if requested by StartServiceResponse.
// It returns an error containing the UsbMux error code should the connect fail.
func (muxConn *UsbMuxConnection) connectWithStartServiceResponse(deviceID int, startServiceResponse StartServiceResponse, pairRecord PairRecord) error {
	err := muxConn.Connect(deviceID, startServiceResponse.Port)
	if err != nil {
		return err
	}

	var sslerr error
	if startServiceResponse.EnableServiceSSL {
		if _, ok := serviceConfigurations[startServiceResponse.Service]; ok {
			sslerr = muxConn.deviceConn.EnableSessionSslHandshakeOnly(pairRecord)
		} else {
			sslerr = muxConn.deviceConn.EnableSessionSsl(pairRecord)
		}
		if sslerr != nil {
			return sslerr
		}
	}

	return nil
}

func ConnectLockdownWithSession(device DeviceEntry) (*LockDownConnection, error) {
	muxConnection, err := NewUsbMuxConnectionSimple()
	if err != nil {
		return nil, fmt.Errorf("USBMuxConnection failed with: %v", err)
	}
	// Keep ownership in muxConnection until the session is fully established.
	// ReleaseDeviceConnection only detaches the pointer; it does not close it.
	defer func() {
		if muxConnection.deviceConn != nil {
			_ = muxConnection.Close()
		}
	}()

	pairRecord, err := muxConnection.ReadPair(device.Properties.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("could not retrieve PairRecord with error: %v", err)
	}

	lockdownConnection, err := muxConnection.ConnectLockdown(device.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("Lockdown connection failed with: %v", err)
	}
	resp, err := lockdownConnection.StartSession(pairRecord)
	if err != nil {
		return nil, fmt.Errorf("StartSession failed: %+v error: %v", resp, err)
	}
	muxConnection.ReleaseDeviceConnection()
	return lockdownConnection, nil
}

func initializeXpcConnection(h *http.HttpConnection) error {
	csWriter := http.NewStreamReadWriter(h, http.ClientServer)
	ssWriter := http.NewStreamReadWriter(h, http.ServerClient)

	err := xpc.EncodeMessage(csWriter, xpc.Message{
		Flags: xpc.AlwaysSetFlag,
		Body:  map[string]interface{}{},
		Id:    0,
	})
	if err != nil {
		return fmt.Errorf("initializeXpcConnection: failed to encode message: %w", err)
	}

	_, err = xpc.DecodeMessage(csWriter) // TODO : figure out if need to act on this frame
	if err != nil {
		return fmt.Errorf("initializeXpcConnection: failed to decode message: %w", err)
	}

	err = xpc.EncodeMessage(ssWriter, xpc.Message{
		Flags: xpc.InitHandshakeFlag | xpc.AlwaysSetFlag,
		Body:  nil,
		Id:    0,
	})
	if err != nil {
		return fmt.Errorf("initializeXpcConnection: failed to encode message 2: %w", err)
	}

	_, err = xpc.DecodeMessage(ssWriter) // TODO : figure out if need to act on this frame
	if err != nil {
		return fmt.Errorf("initializeXpcConnection: failed to decode message 2: %w", err)
	}

	err = xpc.EncodeMessage(csWriter, xpc.Message{
		Flags: 0x201, // alwaysSetFlag | 0x200
		Body:  nil,
		Id:    0,
	})
	if err != nil {
		return fmt.Errorf("initializeXpcConnection: failed to encode message 3: %w", err)
	}

	_, err = xpc.DecodeMessage(csWriter) // TODO : figure out if need to act on this frame
	if err != nil {
		return fmt.Errorf("initializeXpcConnection: failed to decode message 3: %w", err)
	}

	return nil
}

// ConnectTUNDevice creates a *net.TCPConn to the device at the given address and port.
// If the device is a userspaceTUN device provided by go-ios agent, it will connect to this
// automatically. Otherwise it will try a operating system level TUN device.
func ConnectTUNDevice(remoteIp string, port int, d DeviceEntry) (*net.TCPConn, error) {
	if !d.UserspaceTUN {
		return connectTUN(remoteIp, port)
	}

	conn, err := connectUserSpaceTUNDevice(remoteIp, port, d, net.ResolveTCPAddr, func(network string, localAddr, remoteAddr *net.TCPAddr) (userSpaceTUNClientConn, error) {
		return net.DialTCP(network, localAddr, remoteAddr)
	})
	if err != nil {
		return nil, err
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("ConnectUserSpaceTunnel: dialer returned %T instead of *net.TCPConn", conn)
	}
	return tcpConn, nil
}

type userSpaceTUNClientConn interface {
	net.Conn
	SetKeepAlive(bool) error
	SetKeepAlivePeriod(time.Duration) error
}

type userSpaceTUNAddressResolver func(network, address string) (*net.TCPAddr, error)
type userSpaceTUNDialer func(network string, localAddr, remoteAddr *net.TCPAddr) (userSpaceTUNClientConn, error)

func connectUserSpaceTUNDevice(remoteIP string, remotePort int, device DeviceEntry, resolve userSpaceTUNAddressResolver, dial userSpaceTUNDialer) (userSpaceTUNClientConn, error) {
	parsedRemoteIP := net.ParseIP(remoteIP).To16()
	if parsedRemoteIP == nil {
		return nil, fmt.Errorf("ConnectUserSpaceTunnel: invalid remote IP %q", remoteIP)
	}
	if remotePort < 1 || remotePort > 65535 {
		return nil, fmt.Errorf("ConnectUserSpaceTunnel: invalid remote port %d", remotePort)
	}
	if device.UserspaceTUNPort < 1 || device.UserspaceTUNPort > 65535 {
		return nil, fmt.Errorf("ConnectUserSpaceTunnel: invalid userspace tunnel port %d", device.UserspaceTUNPort)
	}
	if strings.TrimSpace(device.UserspaceTUNHost) == "" {
		return nil, errors.New("ConnectUserSpaceTunnel: userspace tunnel host is empty")
	}

	address := net.JoinHostPort(device.UserspaceTUNHost, strconv.Itoa(device.UserspaceTUNPort))
	resolvedAddr, err := resolve("tcp4", address)
	if err != nil {
		return nil, fmt.Errorf("ConnectUserSpaceTunnel: failed to resolve %s: %w", address, err)
	}
	if resolvedAddr == nil {
		return nil, fmt.Errorf("ConnectUserSpaceTunnel: resolver returned a nil address for %s", address)
	}
	conn, err := dial("tcp", nil, resolvedAddr)
	if err != nil {
		return nil, fmt.Errorf("ConnectUserSpaceTunnel: failed to dial: %w", err)
	}
	if conn == nil {
		return nil, errors.New("ConnectUserSpaceTunnel: dialer returned a nil connection")
	}
	keepConn := false
	defer func() {
		if !keepConn {
			_ = conn.Close()
		}
	}()

	if err := conn.SetKeepAlive(true); err != nil {
		return nil, fmt.Errorf("ConnectUserSpaceTunnel: failed to set keepalive: %w", err)
	}
	if err := conn.SetKeepAlivePeriod(1 * time.Second); err != nil {
		return nil, fmt.Errorf("ConnectUserSpaceTunnel: failed to set keepalive period: %w", err)
	}

	header := make([]byte, net.IPv6len+4)
	copy(header, parsedRemoteIP)
	binary.LittleEndian.PutUint32(header[net.IPv6len:], uint32(remotePort))
	if _, err := writeAll(conn, header); err != nil {
		return nil, fmt.Errorf("ConnectUserSpaceTunnel: failed to write destination header: %w", err)
	}
	keepConn = true
	return conn, nil
}

func writeAll(writer io.Writer, data []byte) (int, error) {
	written := 0
	for written < len(data) {
		n, err := writer.Write(data[written:])
		if n < 0 || n > len(data)-written {
			return written, fmt.Errorf("invalid write count %d", n)
		}
		written += n
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrNoProgress
		}
	}
	return written, nil
}

// connect to a operating system level TUN device
func connectTUN(address string, port int) (*net.TCPConn, error) {
	addr, err := net.ResolveTCPAddr("tcp6", fmt.Sprintf("[%s]:%d", address, port))
	if err != nil {
		return nil, fmt.Errorf("ConnectToHttp2WithAddr: failed to resolve address: %w", err)
	}
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("ConnectToHttp2WithAddr: failed to dial: %w", err)
	}
	keepConn := false
	defer func() {
		if !keepConn {
			_ = conn.Close()
		}
	}()
	err = conn.SetKeepAlive(true)
	if err != nil {
		return nil, fmt.Errorf("ConnectUserSpaceTunnel: failed to set keepalive: %w", err)
	}
	err = conn.SetKeepAlivePeriod(1 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("ConnectUserSpaceTunnel: failed to set keepalive period: %w", err)
	}

	keepConn = true
	return conn, nil
}

// defaultHttpApiPort is the port on which we start the HTTP-Server for exposing started tunnels
// 60-105 is leetspeek for go-ios :-D
const defaultHttpApiPort = 60105

// defaultHttpApiHost is the host on which the HTTP-Server runs, by default it is 127.0.0.1
const defaultHttpApiHost = "127.0.0.1"

// DefaultHttpApiPort is the port on which we start the HTTP-Server for exposing started tunnels
// if GO_IOS_AGENT_PORT is set, we use that port. Otherwise we use the default port 60106.
// 60-105 is leetspeek for go-ios :-D
func HttpApiPort() int {
	port, err := strconv.Atoi(os.Getenv("GO_IOS_AGENT_PORT"))
	if err != nil {
		return defaultHttpApiPort
	}
	return port
}

// DefaultHttpApiHost is the host on which the HTTP-Server runs, by default it is 127.0.0.1
// if GO_IOS_AGENT_HOST is set, we use that host. Otherwise we use the default host
func HttpApiHost() string {
	host := os.Getenv("GO_IOS_AGENT_HOST")
	if host == "" {
		return defaultHttpApiHost
	}
	return host
}
