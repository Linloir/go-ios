package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// ioResourceCloser is a type for closing function.
type ioResourceCloser func()

// createIoCloser returns a ioResourceCloser for closing both writer and together
func createIoCloser(rw1, rw2 io.ReadWriteCloser) ioResourceCloser {

	// Using sync.Once is essential to close writer and reader just once
	var once sync.Once
	return func() {
		once.Do(func() {
			rw1.Close()
			rw2.Close()
		})
	}
}

// UserSpaceTUNInterface uses gVisor's netstack to create a userspace virtual network interface.
// You can use it to connect local tcp connections to remote adresses on the network.
// Set it up with the Init method and provide a io.ReadWriter to a IP/TUN compatible device.
// If EnableSniffer, raw TCP packets will be dumped to the console.
type UserSpaceTUNInterface struct {
	nicID tcpip.NICID
	//If EnableSniffer, raw TCP packets will be dumped to the console.
	EnableSniffer bool
	networkStack  *stack.Stack
	endpoint      *Endpoint

	lifecycleMu          sync.Mutex
	closing              bool
	clientCtx            context.Context
	cancelClients        context.CancelFunc
	beforeEndpointCreate func()
	afterEndpointCreate  func()
}

func (iface *UserSpaceTUNInterface) TunnelRWCThroughInterface(localPort uint16, remoteAddr net.IP, remotePort uint16, rw io.ReadWriteCloser) error {
	defer rw.Close()
	remote := tcpip.FullAddress{
		NIC:  iface.nicID,
		Addr: tcpip.AddrFromSlice(remoteAddr.To16()),
		Port: remotePort,
	}

	if iface.beforeEndpointCreate != nil {
		iface.beforeEndpointCreate()
	}
	// Serialize endpoint creation and connect registration with Stack.Close.
	// NewEndpoint alone doesn't register a TCP endpoint with the stack, so the
	// gate remains held through EventRegister and the initial Connect call.
	iface.lifecycleMu.Lock()
	if iface.closing || iface.networkStack == nil {
		iface.lifecycleMu.Unlock()
		return errors.New("TunnelRWCThroughInterface: userspace tunnel is closing")
	}
	clientCtx := iface.clientCtx
	if clientCtx == nil {
		clientCtx = context.Background()
	}
	// Create TCP endpoint.
	var wq waiter.Queue
	ep, err := iface.networkStack.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &wq)
	if err != nil {
		iface.lifecycleMu.Unlock()
		return fmt.Errorf("TunnelRWCThroughInterface: NewEndpoint failed: %+v", err)
	}
	defer ep.Close()
	if iface.afterEndpointCreate != nil {
		iface.afterEndpointCreate()
	}

	ep.SocketOptions().SetKeepAlive(true)
	// Set keep alive idle value more aggresive than the gVisor's 2 hours. NAT and Firewalls can drop the idle connections more aggresive.
	p := tcpip.KeepaliveIdleOption(30 * time.Second)
	ep.SetSockOpt(&p)

	o := tcpip.KeepaliveIntervalOption(1 * time.Second)
	ep.SetSockOpt(&o)

	// Bind if a port is specified.
	if localPort != 0 {
		if err := ep.Bind(tcpip.FullAddress{Port: localPort}); err != nil {
			iface.lifecycleMu.Unlock()
			return fmt.Errorf("TunnelRWCThroughInterface: Bind failed: %+v", err)
		}
	}
	// Issue connect request and wait for it to complete.
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&waitEntry)
	err = ep.Connect(remote)
	iface.lifecycleMu.Unlock()
	var connectContextErr error
	if _, ok := err.(*tcpip.ErrConnectStarted); ok {
		select {
		case <-notifyCh:
			err = ep.LastError()
		case <-clientCtx.Done():
			connectContextErr = fmt.Errorf("userspace tunnel closed while connecting: %w", clientCtx.Err())
		}
	}
	wq.EventUnregister(&waitEntry)
	if connectContextErr != nil {
		return connectContextErr
	}
	if err != nil {
		return fmt.Errorf("TunnelRWCThroughInterface: Connect to remote failed: %+v", err)
	}

	slog.Info("Connected to ", "remoteAddr", remoteAddr, "remotePort", remotePort)
	remoteConn := gonet.NewTCPConn(&wq, ep)
	defer remoteConn.Close()
	perr := proxyConns(rw, remoteConn)
	if perr != nil {
		return fmt.Errorf("TunnelRWCThroughInterface: proxyConns failed: %+v", perr)
	}
	return nil
}

func proxyConns(rw1 io.ReadWriteCloser, rw2 io.ReadWriteCloser) error {

	// Use buffered channel for non-blocking send recieve. We use the same single channel 2 times for 2 ioCopyWithErr.
	errCh := make(chan error, 2)

	// Create a IO closing functions to unblock stuck io.Copy() call
	ioCloser := createIoCloser(rw1, rw2)

	// Send same error channel and the io close function
	go ioCopyWithErr(rw1, rw2, errCh, ioCloser)
	go ioCopyWithErr(rw2, rw1, errCh, ioCloser)

	// Read from error channel. As the channel is a FIFO queue first in first out, each <-errCh will read one message and remove it from the channel.
	// Order of messages are not important.
	err1 := <-errCh
	err2 := <-errCh

	return errors.Join(err1, err2)
}

func ioCopyWithErr(w io.Writer, r io.Reader, errCh chan error, ioCloser ioResourceCloser) {
	_, err := io.Copy(w, r)
	errCh <- err

	// Close the writer and reader to notify the second io.Copy() if one part of the connection closed.
	// This is also necessary to avoid resource leaking.
	ioCloser()
}

// Init initializes the virtual network interface.
// The connToTUNIface needs to be connection that understands IP packets to a remote TUN device or sth.
// provide mtu, ip address as a string and the prefix length of the interface.
func (iface *UserSpaceTUNInterface) Init(mtu uint32, connToTUNIface io.ReadWriteCloser, ipAddrString string, prefixLength int) error {
	addr := tcpip.AddrFromSlice(net.ParseIP(ipAddrString).To16())
	addrWithPrefix := addr.WithPrefix()
	addrWithPrefix.PrefixLen = prefixLength

	//Create a new stack, ipv6 is enough for ios devices
	iface.networkStack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	iface.clientCtx, iface.cancelClients = context.WithCancel(context.Background())

	// connToTUNIface needs to be connection that understands IP packets,
	// so we can use it to link it against a virtual network interface
	var linkEP stack.LinkEndpoint
	endpoint, err := RWCEndpointNew(connToTUNIface, mtu, 0)
	if err != nil {
		return fmt.Errorf("initVirtualInterface: RWCEndpointNew failed: %+v", err)
	}
	iface.endpoint = endpoint
	linkEP = endpoint

	nicID := tcpip.NICID(iface.networkStack.UniqueID())
	iface.nicID = nicID
	if iface.EnableSniffer {
		linkEP = sniffer.New(linkEP)
	}
	if err := iface.networkStack.CreateNIC(nicID, linkEP); err != nil {
		return fmt.Errorf("initVirtualInterface: CreateNIC failed: %+v", err)
	}

	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          ipv6.ProtocolNumber,
		AddressWithPrefix: addrWithPrefix,
	}
	if err := iface.networkStack.AddProtocolAddress(iface.nicID, protocolAddr, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("initVirtualInterface: AddProtocolAddress(%d, %v, {}): %+v", nicID, protocolAddr, err)
	}

	// Add default route.
	iface.networkStack.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         nicID,
		},
	})
	return nil
}

func (iface *UserSpaceTUNInterface) closeStackAndWait() {
	if iface == nil {
		return
	}
	iface.lifecycleMu.Lock()
	iface.closing = true
	if iface.cancelClients != nil {
		iface.cancelClients()
	}
	networkStack := iface.networkStack
	if networkStack != nil {
		networkStack.Close()
	}
	iface.lifecycleMu.Unlock()
	if networkStack != nil {
		networkStack.Wait()
	}
	iface.waitTransport()
}

func (iface *UserSpaceTUNInterface) transportDone() <-chan struct{} {
	if iface == nil || iface.endpoint == nil {
		return nil
	}
	return iface.endpoint.Done()
}

func (iface *UserSpaceTUNInterface) waitTransport() {
	if iface != nil && iface.endpoint != nil {
		iface.endpoint.Wait()
	}
}

func ConnectUserSpaceTunnelLockdown(device ios.DeviceEntry, ifacePort int) (Tunnel, error) {
	return ConnectUserSpaceTunnelLockdownContext(context.Background(), device, ifacePort)
}

func ConnectUserSpaceTunnelLockdownContext(ctx context.Context, device ios.DeviceEntry, ifacePort int) (Tunnel, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Tunnel{}, err
	}
	conn, err := ios.ConnectToServiceContext(ctx, device, coreDeviceProxy)
	if err != nil {
		return Tunnel{}, err
	}
	return connectToUserspaceTunnelLockdown(ctx, device, conn, ifacePort)
}

func connectToUserspaceTunnelLockdown(ctx context.Context, device ios.DeviceEntry, connToDevice io.ReadWriteCloser, ifacePort int) (Tunnel, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		_ = connToDevice.Close()
		return Tunnel{}, err
	}
	setupCloseDone := make(chan struct{})
	stopSetupClose := context.AfterFunc(ctx, func() {
		defer close(setupCloseDone)
		_ = connToDevice.Close()
	})
	stopSetupWatcher := func() bool {
		stopped := stopSetupClose()
		if !stopped {
			<-setupCloseDone
		}
		return stopped
	}
	setupWatcherActive := true
	defer func() {
		if setupWatcherActive {
			stopSetupWatcher()
		}
	}()

	slog.Info("connect to lockdown tunnel endpoint on device")
	tunnelInfo, err := exchangeCoreTunnelParameters(connToDevice)
	if err != nil {
		_ = connToDevice.Close()
		return Tunnel{}, coreTunnelSetupError(ctx, "could not exchange tunnel parameters", err)
	}
	const prefixLength = 64
	// The lockdown tunnel carries raw IPv6 packets over a TCP byte stream.
	// Preserve packet boundaries before handing reads to gVisor.
	framedConn := newFramedIPv6Conn(connToDevice)
	iface := UserSpaceTUNInterface{}
	err = iface.Init(uint32(tunnelInfo.ClientParameters.Mtu), framedConn, tunnelInfo.ClientParameters.Address, prefixLength)
	if err != nil {
		_ = connToDevice.Close()
		iface.closeStackAndWait()
		return Tunnel{}, coreTunnelSetupError(ctx, "could not setup tunnel interface", err)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", ifacePort))
	if err != nil {
		_ = connToDevice.Close()
		iface.closeStackAndWait()
		return Tunnel{}, coreTunnelSetupError(ctx, "could not setup listener", err)
	}

	server := newUserspaceTunnelServer(&iface, listener)
	closeResources := func() error {
		listenerErr := server.close()
		connErr := connToDevice.Close()
		iface.closeStackAndWait()
		server.wait()
		return errors.Join(listenerErr, connErr)
	}
	runtime := startUserspaceLockdownTunnelRuntime(ctx, server.serve, iface.transportDone(), closeResources)
	if !stopSetupWatcher() {
		setupWatcherActive = false
		_ = runtime.closeAndWait()
		return Tunnel{}, coreTunnelSetupError(ctx, "userspace tunnel setup canceled", nil)
	}
	setupWatcherActive = false
	if err := ctx.Err(); err != nil {
		_ = runtime.closeAndWait()
		return Tunnel{}, err
	}
	return Tunnel{
		Address: tunnelInfo.ServerAddress,
		RsdPort: int(tunnelInfo.ServerRSDPort),
		Udid:    device.Properties.SerialNumber,
		runtime: runtime,
	}, nil
}

func startUserspaceLockdownTunnelRuntime(ctx context.Context, serve func() error, transportDone <-chan struct{}, closeResources func() error) *tunnelRuntime {
	return newTunnelRuntime(ctx, closeResources,
		tunnelRuntimeWorker{name: "userspace listener", run: func(context.Context) error {
			return serve()
		}},
		tunnelRuntimeWorker{name: "userspace transport", run: func(workerCtx context.Context) error {
			select {
			case <-transportDone:
				return errors.New("link endpoint stopped")
			case <-workerCtx.Done():
				return nil
			}
		}},
	)
}

type userspaceTunnelServer struct {
	iface    *UserSpaceTUNInterface
	listener net.Listener

	mu       sync.Mutex
	closing  bool
	clients  map[net.Conn]struct{}
	clientsW sync.WaitGroup
	closeOne sync.Once
	closeErr error
}

func newUserspaceTunnelServer(iface *UserSpaceTUNInterface, listener net.Listener) *userspaceTunnelServer {
	return &userspaceTunnelServer{
		iface:    iface,
		listener: listener,
		clients:  make(map[net.Conn]struct{}),
	}
}

func (s *userspaceTunnelServer) serve() error {
	defer slog.Info("Stopped listening for connections")
	for {
		client, err := s.listener.Accept()
		if err != nil {
			return err
		}

		s.mu.Lock()
		if s.closing {
			s.mu.Unlock()
			_ = client.Close()
			continue
		}
		s.clients[client] = struct{}{}
		s.clientsW.Add(1)
		s.mu.Unlock()

		go func() {
			defer s.clientsW.Done()
			defer func() {
				s.mu.Lock()
				delete(s.clients, client)
				s.mu.Unlock()
			}()
			handleUserspaceClient(s.iface, client)
		}()
	}
}

func (s *userspaceTunnelServer) close() error {
	s.closeOne.Do(func() {
		s.mu.Lock()
		s.closing = true
		clients := make([]net.Conn, 0, len(s.clients))
		for client := range s.clients {
			clients = append(clients, client)
		}
		s.mu.Unlock()

		listenerErr := s.listener.Close()
		if errors.Is(listenerErr, net.ErrClosed) {
			listenerErr = nil
		}
		var clientsErr error
		for _, client := range clients {
			clientsErr = errors.Join(clientsErr, client.Close())
		}
		s.closeErr = errors.Join(listenerErr, clientsErr)
	})
	return s.closeErr
}

func (s *userspaceTunnelServer) wait() {
	s.clientsW.Wait()
}

func listenToConns(iface *UserSpaceTUNInterface, listener net.Listener) error {
	server := newUserspaceTunnelServer(iface, listener)
	defer server.wait()
	defer server.close()
	return server.serve()
}

func handleUserspaceClient(iface *UserSpaceTUNInterface, client net.Conn) {
	slog.Info("Received connection request", "from", client.RemoteAddr(), "to", client.LocalAddr())
	// Defensive deadline so a stalled / partial-handshake client cannot
	// pin a goroutine forever before sending the 20-byte preamble.
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))

	preamble := make([]byte, 20)
	if _, err := io.ReadFull(client, preamble); err != nil {
		slog.Debug("userspace TUN: short or failed preamble; dropping client",
			"err", err)
		_ = client.Close()
		return
	}
	_ = client.SetReadDeadline(time.Time{})

	remoteAddrBytes := preamble[:16]
	port := binary.LittleEndian.Uint32(preamble[16:])
	slog.Info("Received connection request to device ", "ip", net.IP(remoteAddrBytes), "port", port)
	// TunnelRWCThroughInterface owns Close on client.
	if err := iface.TunnelRWCThroughInterface(0, net.IP(remoteAddrBytes), uint16(port), client); err != nil {
		slog.Debug("userspace TUN forward error", "err", err)
	}
}
