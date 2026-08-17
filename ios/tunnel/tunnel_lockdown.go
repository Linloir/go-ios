package tunnel

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/sirupsen/logrus"
)

const coreDeviceProxy = "com.apple.internal.devicecompute.CoreDeviceProxy"

func ConnectTunnelLockdown(device ios.DeviceEntry) (Tunnel, error) {
	return ConnectTunnelLockdownContext(context.Background(), device)
}

func ConnectTunnelLockdownContext(ctx context.Context, device ios.DeviceEntry) (Tunnel, error) {
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
	return connectToTunnelLockdown(ctx, device, conn)
}

func connectToTunnelLockdown(ctx context.Context, device ios.DeviceEntry, connToDevice io.ReadWriteCloser) (Tunnel, error) {
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

	logrus.Info("connect to lockdown tunnel endpoint on device")

	tunnelInfo, err := exchangeCoreTunnelParameters(connToDevice)
	if err != nil {
		_ = connToDevice.Close()
		return Tunnel{}, coreTunnelSetupError(ctx, "could not exchange tunnel parameters", err)
	}

	utunIface, err := setupTunnelInterface(tunnelInfo)
	if err != nil {
		_ = connToDevice.Close()
		return Tunnel{}, coreTunnelSetupError(ctx, "could not setup tunnel interface", err)
	}

	runtime := startLockdownKernelTunnelRuntime(ctx, connToDevice, utunIface, tunnelInfo.ClientParameters.Mtu)
	if !stopSetupWatcher() {
		setupWatcherActive = false
		_ = runtime.closeAndWait()
		return Tunnel{}, coreTunnelSetupError(ctx, "lockdown tunnel setup canceled", nil)
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

func coreTunnelSetupError(ctx context.Context, operation string, err error) error {
	if ctx != nil && ctx.Err() != nil {
		err = errors.Join(ctx.Err(), err)
	}
	if err == nil {
		err = context.Canceled
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func startLockdownKernelTunnelRuntime(ctx context.Context, connToDevice, utunIface io.ReadWriteCloser, mtu uint64) *tunnelRuntime {
	closeResources := func() error {
		return errors.Join(connToDevice.Close(), utunIface.Close())
	}
	return newTunnelRuntime(ctx, closeResources,
		tunnelRuntimeWorker{name: "lockdown receive forwarding", run: func(workerCtx context.Context) error {
			return forwardTCPToInterface(workerCtx, mtu, connToDevice, utunIface)
		}},
		tunnelRuntimeWorker{name: "lockdown send forwarding", run: func(workerCtx context.Context) error {
			return forwardTUNToDevice(workerCtx, mtu, utunIface, connToDevice)
		}},
	)
}

func forwardTUNToDevice(ctx context.Context, mtu uint64, tun io.Reader, deviceConn io.Writer) error {
	packet := make([]byte, mtu)
	for {

		select {
		case <-ctx.Done():
			return nil
		default:

			n, err := tun.Read(packet)

			if err != nil {
				return fmt.Errorf("could not read packet. %w", err)
			}

			_, err = deviceConn.Write(packet[:n])
			if err != nil {
				return fmt.Errorf("could not write packet. %w", err)
			}
		}

	}
}

func forwardTCPToInterface(ctx context.Context, mtu uint64, deviceConn io.Reader, tun io.Writer) error {
	payload := make([]byte, mtu)
	ip6Header := make([]byte, 40)

	br := bufio.NewReader(deviceConn)
	bw := bufio.NewWriter(tun)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			_, err := io.ReadFull(br, ip6Header)
			if err != nil {
				return fmt.Errorf("failed to read IPv6 header: %w", err)
			}

			if ip6Header[0]>>4 != 6 {
				return fmt.Errorf("not an IPv6 packet: expected version 6, got %d", ip6Header[0]>>4)
			}
			payloadLength := binary.BigEndian.Uint16(ip6Header[4:6])
			_, err = io.ReadFull(br, payload[:payloadLength])
			if err != nil {
				return fmt.Errorf("failed to read payload of length %d: %w", payloadLength, err)
			}

			// we don't need to check all errors here as `Flush` will return the error from a previous write as well
			_, _ = bw.Write(ip6Header)
			_, _ = bw.Write(payload[:payloadLength])
			err = bw.Flush()
			if err != nil {
				return fmt.Errorf("could not flush packet: %w", err)
			}
		}

	}
}
