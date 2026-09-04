package debugserver

import (
	"net"
	"testing"
	"time"
)

func TestRelayDebugConnectionsStopsBothDirectionsOnDeviceEOF(t *testing.T) {
	localProxy, localPeer := net.Pipe()
	deviceProxy, devicePeer := net.Pipe()
	defer localPeer.Close()

	done := make(chan struct{})
	go func() {
		relayDebugConnections(localProxy, deviceProxy)
		close(done)
	}()
	_ = devicePeer.Close()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("debug relay did not stop after device-side EOF")
	}
	if _, err := localPeer.Write([]byte("after EOF")); err == nil {
		t.Fatal("local connection remained open after device-side EOF")
	}
}
