package forward

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/danielpaulus/go-ios/ios"
	log "github.com/sirupsen/logrus"
)

type iosproxy struct {
	tcpConn    net.Conn
	deviceConn ios.DeviceConnectionInterface
}

type ConnListener struct {
	listener  net.Listener
	quit      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// Forward forwards every connection made to the hostPort to whatever service runs inside an app on the device on phonePort.
// Port values must be between 1 and 65535.
func Forward(device ios.DeviceEntry, hostPort uint16, phonePort uint16) (*ConnListener, error) {
	if hostPort == 0 {
		return nil, fmt.Errorf("forward: invalid host port: port must be at least 1")
	}
	if phonePort == 0 {
		return nil, fmt.Errorf("forward: invalid target port: port must be at least 1")
	}
	listenAddress := forwardListenAddress(hostPort)
	log.Infof("Start listening on %s forwarding to port %d on device", listenAddress, phonePort)
	l, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return nil, fmt.Errorf("forward: failed listener with err: %w", err)
	}
	cl := &ConnListener{
		listener: l,
		quit:     make(chan struct{}),
	}

	go connectionAccept(cl, device.DeviceID, phonePort)

	return cl, nil
}

func forwardListenAddress(hostPort uint16) string {
	return net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", hostPort))
}

// Close stops listening on the host port for the forwarded connection
func (cl *ConnListener) Close() error {
	cl.closeOnce.Do(func() {
		close(cl.quit)
		if err := cl.listener.Close(); err != nil {
			cl.closeErr = fmt.Errorf("forward: failed closing listener with err: %w", err)
		}
	})
	return cl.closeErr
}

func connectionAccept(cl *ConnListener, deviceID int, phonePort uint16) {
	for {
		select {
		case <-cl.quit:
			log.WithFields(log.Fields{"phonePort": phonePort}).Info("closed listener successfully")
			return
		default:
			clientConn, err := cl.listener.Accept()
			if err != nil {
				select {
				case <-cl.quit:
					return
				default:
				}
				log.Errorf("Error accepting new connection %v", err)
				continue
			}
			log.WithFields(log.Fields{"conn": fmt.Sprintf("%#v", cl)}).Info("new client connected")
			go StartNewProxyConnection(context.TODO(), clientConn, deviceID, phonePort)
		}
	}
}

func StartNewProxyConnection(ctx context.Context, clientConn io.ReadWriteCloser, deviceID int, phonePort uint16) error {
	usbmuxConn, err := ios.NewUsbMuxConnectionSimple()
	if err != nil {
		log.Errorf("could not connect to usbmuxd: %+v", err)
		_ = clientConn.Close()
		return fmt.Errorf("could not connect to usbmuxd: %w", err)
	}
	muxError := usbmuxConn.Connect(deviceID, phonePort)
	if muxError != nil {
		log.WithFields(log.Fields{"conn": fmt.Sprintf("%#v", clientConn), "err": muxError, "phonePort": phonePort}).Infof("could not connect to phone")
		_ = clientConn.Close()
		_ = usbmuxConn.Close()
		return fmt.Errorf("could not connect to port:%d on iOS: %w", phonePort, muxError)
	}
	log.WithFields(log.Fields{"conn": fmt.Sprintf("%#v", clientConn), "phonePort": phonePort}).Infof("Connected to port")
	deviceConn := usbmuxConn.ReleaseDeviceConnection()

	var closeOnce sync.Once
	closeConnections := func() {
		closeOnce.Do(func() {
			_ = clientConn.Close()
			_ = deviceConn.Close()
		})
	}
	defer closeConnections()

	var wg sync.WaitGroup
	done := make(chan struct{})
	copyConnection := func(direction string, dst io.Writer, src io.Reader) {
		defer wg.Done()
		if _, err := io.Copy(dst, src); err != nil {
			log.WithError(err).Debugf("forward: copy failed %s", direction)
		}
		closeConnections()
	}
	wg.Add(2)
	go copyConnection("client <-- device", clientConn, deviceConn.Reader())
	go copyConnection("client --> device", deviceConn.Writer(), clientConn)
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		closeConnections()
		<-done
	case <-done:
	}
	return nil
}

func (proxyConn *iosproxy) Close() {
	proxyConn.tcpConn.Close()
}
