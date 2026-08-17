package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/danielpaulus/go-ios/ios"
)

func startBlockedPairRecordUsbmux(t *testing.T) (string, <-chan struct{}, <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	requestReceived := make(chan struct{})
	clientClosed := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			close(requestReceived)
			close(clientClosed)
			return
		}
		defer conn.Close()

		var header ios.UsbMuxHeader
		if err := binary.Read(conn, binary.LittleEndian, &header); err == nil && header.Length >= 16 {
			payload := make([]byte, header.Length-16)
			_, _ = io.ReadFull(conn, payload)
		}
		close(requestReceived)
		_, _ = io.Copy(io.Discard, conn)
		close(clientClosed)
	}()
	return listener.Addr().String(), requestReceived, clientClosed
}

func TestPublicCoreTunnelConstructorsCancelBlockedServiceSetup(t *testing.T) {
	constructors := []struct {
		name string
		call func(context.Context, ios.DeviceEntry) (Tunnel, error)
	}{
		{
			name: "kernel",
			call: ConnectTunnelLockdownContext,
		},
		{
			name: "userspace",
			call: func(ctx context.Context, device ios.DeviceEntry) (Tunnel, error) {
				return ConnectUserSpaceTunnelLockdownContext(ctx, device, 0)
			},
		},
	}

	for _, constructor := range constructors {
		t.Run(constructor.name, func(t *testing.T) {
			socketAddress, requestReceived, clientClosed := startBlockedPairRecordUsbmux(t)
			t.Setenv("USBMUXD_SOCKET_ADDRESS", socketAddress)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				_, err := constructor.call(ctx, ios.DeviceEntry{
					DeviceID: 1,
					Properties: ios.DeviceProperties{
						SerialNumber: "test-udid",
					},
				})
				result <- err
			}()

			select {
			case <-requestReceived:
			case <-time.After(time.Second):
				t.Fatal("public constructor did not reach the blocked ReadPair stage")
			}
			cancel()

			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("constructor error = %v, want context.Canceled", err)
				}
			case <-time.After(time.Second):
				t.Fatal("public constructor did not return after cancellation")
			}
			select {
			case <-clientClosed:
			case <-time.After(time.Second):
				t.Fatal("public constructor did not close the blocked usbmux connection")
			}
		})
	}
}
