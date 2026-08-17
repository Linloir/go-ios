package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os/exec"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/http"

	"github.com/quic-go/quic-go"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

// Tunnel describes the parameters of an established tunnel to the device
type Tunnel struct {
	// Address is the IPv6 address of the device over the tunnel
	Address string `json:"address"`
	// RsdPort is the port on which remote service discover is reachable
	RsdPort int `json:"rsdPort"`
	// Udid is the id of the device for this tunnel
	Udid string `json:"udid"`
	// Userspace TUN device is used, connect to the local tcp port at Default
	UserspaceTUN     bool `json:"userspaceTun"`
	UserspaceTUNPort int  `json:"userspaceTunPort"`
	closer           func() error
	// runtime is deliberately not serialized. It carries the shared liveness,
	// error, and join state for every copy of this tunnel value.
	runtime *tunnelRuntime
	// generation is assigned by TunnelManager whenever a tunnel is published.
	// It is deliberately not serialized: it only prevents a delayed stop for an
	// old attachment from removing or closing its replacement.
	generation uint64
	// attachment identifies the usbmux attachment that produced this tunnel.
	// A device can detach and reattach with the same UDID between two polls; its
	// usbmux DeviceID (and often LocationID) changes even though the key does not.
	attachment tunnelAttachmentFingerprint
}

type tunnelAttachmentFingerprint struct {
	deviceID   int
	locationID int
}

// Close closes the connection to the device and removes the virtual network interface from the host
func (t Tunnel) Close() error {
	if t.runtime != nil {
		return t.runtime.closeAndWait()
	}
	if t.closer == nil {
		return nil
	}
	return t.closer()
}

// Done is closed after a production tunnel has stopped and all of its critical
// workers have joined. Tunnels decoded from the HTTP API have no local runtime
// and therefore return nil.
func (t Tunnel) Done() <-chan struct{} {
	if t.runtime == nil {
		return nil
	}
	return t.runtime.done
}

// Err reports why a production tunnel stopped. It remains nil for an explicit
// clean Close unless resource cleanup itself failed.
func (t Tunnel) Err() error {
	if t.runtime == nil {
		return nil
	}
	return t.runtime.err()
}

func (t Tunnel) alive() bool {
	return t.runtime == nil || t.runtime.alive()
}

// ManualPairAndConnectToTunnel tries to verify an existing pairing, and if this fails it triggers a new manual pairing process.
// After a successful pairing a tunnel for this device gets started and the tunnel information is returned
func ManualPairAndConnectToTunnel(ctx context.Context, device ios.DeviceEntry, p PairRecordManager) (Tunnel, error) {
	log.Info("ManualPairAndConnectToTunnel: starting manual pairing and tunnel connection, dont forget to stop remoted first with 'sudo pkill -SIGSTOP remoted' and run this with sudo.")
	addr, err := ios.FindDeviceInterfaceAddress(ctx, device)
	if err != nil {
		return Tunnel{}, fmt.Errorf("ManualPairAndConnectToTunnel: failed to find device ethernet interface: %w", err)
	}

	port, err := getUntrustedTunnelServicePort(addr, device)
	if err != nil {
		return Tunnel{}, fmt.Errorf("ManualPairAndConnectToTunnel: could not find port for '%s'", untrustedTunnelServiceName)
	}
	conn, err := ios.ConnectTUNDevice(addr, port, device)
	if err != nil {
		return Tunnel{}, fmt.Errorf("ManualPairAndConnectToTunnel: failed to connect to TUN device: %w", err)
	}
	h, err := http.NewHttpConnection(conn)
	if err != nil {
		return Tunnel{}, fmt.Errorf("ManualPairAndConnectToTunnel: failed to create HTTP2 connection: %w", err)
	}

	xpcConn, err := ios.CreateXpcConnection(h)
	if err != nil {
		return Tunnel{}, fmt.Errorf("ManualPairAndConnectToTunnel: failed to create RemoteXPC connection: %w", err)
	}
	ts := newTunnelServiceWithXpc(xpcConn, h, p)

	err = ts.ManualPair()
	if err != nil {
		return Tunnel{}, fmt.Errorf("ManualPairAndConnectToTunnel: failed to pair device: %w", err)
	}
	tunnelInfo, err := ts.createTunnelListener()
	if err != nil {
		return Tunnel{}, fmt.Errorf("ManualPairAndConnectToTunnel: failed to create tunnel listener: %w", err)
	}
	t, err := connectToTunnel(ctx, tunnelInfo, addr, device)
	if err != nil {
		return Tunnel{}, fmt.Errorf("ManualPairAndConnectToTunnel: failed to connect to tunnel: %w", err)
	}
	return t, nil
}

func getUntrustedTunnelServicePort(addr string, device ios.DeviceEntry) (int, error) {
	rsdService, err := ios.NewWithAddrDevice(addr, device)
	if err != nil {
		return 0, fmt.Errorf("getUntrustedTunnelServicePort: failed to connect to RSD service: %w", err)
	}
	defer rsdService.Close()
	handshakeResponse, err := rsdService.Handshake()
	if err != nil {
		return 0, fmt.Errorf("getUntrustedTunnelServicePort: failed to perform RSD handshake: %w", err)
	}

	port := handshakeResponse.GetPort(untrustedTunnelServiceName)
	if port == 0 {
		return 0, fmt.Errorf("getUntrustedTunnelServicePort: could not find port for '%s'", untrustedTunnelServiceName)
	}
	return port, nil
}

func connectToTunnel(ctx context.Context, info tunnelListener, addr string, device ios.DeviceEntry) (Tunnel, error) {
	logrus.WithField("address", addr).WithField("port", info.TunnelPort).Info("connect to tunnel endpoint on device")

	conf, err := createTlsConfig(info)
	if err != nil {
		return Tunnel{}, err
	}

	conn, err := quic.DialAddr(ctx, fmt.Sprintf("[%s]:%d", addr, info.TunnelPort), conf, &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 1 * time.Second,
	})
	if err != nil {
		return Tunnel{}, err
	}

	err = conn.SendDatagram(make([]byte, 1024))
	if err != nil {
		_ = conn.CloseWithError(0, "tunnel bootstrap datagram failed")
		return Tunnel{}, err
	}

	stream, err := conn.OpenStream()
	if err != nil {
		_ = conn.CloseWithError(0, "tunnel handshake stream failed")
		return Tunnel{}, err
	}

	tunnelInfo, err := exchangeCoreTunnelParameters(stream)
	_ = stream.Close()
	if err != nil {
		_ = conn.CloseWithError(0, "tunnel parameter exchange failed")
		return Tunnel{}, fmt.Errorf("could not exchange tunnel parameters. %w", err)
	}

	utunIface, err := setupTunnelInterface(tunnelInfo)
	if err != nil {
		_ = conn.CloseWithError(0, "tunnel interface setup failed")
		return Tunnel{}, fmt.Errorf("could not setup tunnel interface. %w", err)
	}

	runtime := startQUICKernelTunnelRuntime(ctx, conn, utunIface, tunnelInfo.ClientParameters.Mtu)

	return Tunnel{
		Address: tunnelInfo.ServerAddress,
		RsdPort: int(tunnelInfo.ServerRSDPort),
		Udid:    device.Properties.SerialNumber,
		runtime: runtime,
	}, nil
}

type tunnelDatagramConnection interface {
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
	CloseWithError(quic.ApplicationErrorCode, string) error
	Context() context.Context
}

func startQUICKernelTunnelRuntime(ctx context.Context, conn tunnelDatagramConnection, utunIface io.ReadWriteCloser, mtu uint64) *tunnelRuntime {
	closeResources := func() error {
		// Closing both directions is required: ReceiveDatagram is released by the
		// QUIC close while a blocking TUN Read is released by closing the interface.
		return errors.Join(
			conn.CloseWithError(0, ""),
			utunIface.Close(),
		)
	}
	return newTunnelRuntime(ctx, closeResources,
		tunnelRuntimeWorker{name: "QUIC receive forwarding", run: func(workerCtx context.Context) error {
			return forwardDataToInterface(workerCtx, conn, utunIface)
		}},
		tunnelRuntimeWorker{name: "QUIC send forwarding", run: func(workerCtx context.Context) error {
			return forwardDataToDevice(workerCtx, mtu, utunIface, conn)
		}},
		tunnelRuntimeWorker{name: "QUIC transport", run: func(context.Context) error {
			<-conn.Context().Done()
			if err := context.Cause(conn.Context()); err != nil {
				return err
			}
			return conn.Context().Err()
		}},
	)
}

func runCmd(cmd *exec.Cmd) error {
	buf := new(bytes.Buffer)
	cmd.Stderr = buf
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("runCmd: failed to exeute command (stderr: %s): %w", buf.String(), err)
	}
	return nil
}

func createTlsConfig(info tunnelListener) (*tls.Config, error) {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template, &info.PrivateKey.PublicKey, info.PrivateKey)
	if err != nil {
		return nil, err
	}
	privateKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(info.PrivateKey),
		},
	)
	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	cert5, err := tls.X509KeyPair(certPem, privateKeyPem)

	conf := &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{cert5},
		ClientAuth:         tls.NoClientCert,
		NextProtos:         []string{"RemotePairingTunnelProtocol"},
		CurvePreferences:   []tls.CurveID{tls.CurveP256},
	}
	return conf, nil
}

func forwardDataToDevice(ctx context.Context, mtu uint64, r io.Reader, conn tunnelDatagramConnection) error {
	packet := make([]byte, mtu)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			n, err := r.Read(packet)
			if err != nil {
				return fmt.Errorf("could not read packet. %w", err)
			}
			err = conn.SendDatagram(packet[:n])
			if err != nil {
				return fmt.Errorf("could not write packet. %w", err)
			}
		}
	}
}

func forwardDataToInterface(ctx context.Context, conn tunnelDatagramConnection, w io.Writer) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			b, err := conn.ReceiveDatagram(ctx)
			if err != nil {
				return fmt.Errorf("failed to read datagram. %w", err)
			}
			_, err = w.Write(b)
			if err != nil {
				return fmt.Errorf("failed to forward data. %w", err)
			}
		}
	}
}

func exchangeCoreTunnelParameters(stream io.ReadWriteCloser) (tunnelParameters, error) {
	rq, err := json.Marshal(map[string]interface{}{
		"type": "clientHandshakeRequest",
		"mtu":  1280,
	})
	if err != nil {
		return tunnelParameters{}, err
	}

	// The wire prefix is the eight-byte ASCII magic followed immediately by a
	// uint16 big-endian length. For bodies below 256 bytes the high length byte
	// is zero, which makes captures appear as "CDTunnel\0".
	const magic = "CDTunnel"
	if len(rq) > int(^uint16(0)) {
		return tunnelParameters{}, fmt.Errorf("CoreDevice tunnel request is too large: %d", len(rq))
	}
	request := make([]byte, len(magic)+2+len(rq))
	copy(request, magic)
	binary.BigEndian.PutUint16(request[len(magic):], uint16(len(rq)))
	copy(request[len(magic)+2:], rq)
	if err := writeCoreTunnelFrame(stream, request); err != nil {
		return tunnelParameters{}, fmt.Errorf("could not write CoreDevice tunnel request: %w", err)
	}

	header := make([]byte, len(magic)+2)
	if _, err := io.ReadFull(stream, header); err != nil {
		return tunnelParameters{}, fmt.Errorf("could not read CoreDevice tunnel response header: %w", err)
	}
	if !bytes.Equal(header[:len(magic)], []byte(magic)) {
		return tunnelParameters{}, fmt.Errorf("invalid CoreDevice tunnel response magic %q", header[:len(magic)])
	}
	bodyLen := int(binary.BigEndian.Uint16(header[len(magic):]))
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(stream, body); err != nil {
		return tunnelParameters{}, fmt.Errorf("could not read CoreDevice tunnel response body (%d bytes): %w", bodyLen, err)
	}

	var parameters tunnelParameters
	if err := json.Unmarshal(body, &parameters); err != nil {
		return tunnelParameters{}, fmt.Errorf("could not decode CoreDevice tunnel response: %w", err)
	}
	return parameters, nil
}

func writeCoreTunnelFrame(writer io.Writer, frame []byte) error {
	written := 0
	for written < len(frame) {
		n, err := writer.Write(frame[written:])
		if n < 0 || n > len(frame)-written {
			return fmt.Errorf("invalid write count %d", n)
		}
		written += n
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}
