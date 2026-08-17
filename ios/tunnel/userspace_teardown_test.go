package tunnel

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUserspaceTeardownGatesBeforeEndpointCreation(t *testing.T) {
	testUserspaceEndpointTeardownGate(t, false)
}

func TestUserspaceTeardownGatesAfterEndpointCreationBeforeConnect(t *testing.T) {
	testUserspaceEndpointTeardownGate(t, true)
}

func testUserspaceEndpointTeardownGate(t *testing.T, pauseAfterEndpoint bool) {
	tunTransport, tunPeer := net.Pipe()
	defer tunPeer.Close()
	iface := &UserSpaceTUNInterface{}
	require.NoError(t, iface.Init(1280, tunTransport, "fd00::1", 64))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := newUserspaceTunnelServer(iface, listener)
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.serve() }()

	beforeEndpoint := make(chan struct{})
	releaseEndpoint := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseEndpoint) }) }
	defer release()
	pause := func() {
		close(beforeEndpoint)
		<-releaseEndpoint
	}
	if pauseAfterEndpoint {
		iface.afterEndpointCreate = pause
	} else {
		iface.beforeEndpointCreate = pause
	}

	client, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer client.Close()
	header := make([]byte, 20)
	copy(header, net.ParseIP("fd00::2").To16())
	binary.LittleEndian.PutUint32(header[16:], 62078)
	_, err = client.Write(header)
	require.NoError(t, err)
	select {
	case <-beforeEndpoint:
	case <-time.After(time.Second):
		t.Fatal("client did not pause before endpoint creation")
	}

	teardownDone := make(chan struct{})
	go func() {
		_ = server.close()
		_ = tunTransport.Close()
		iface.closeStackAndWait()
		server.wait()
		close(teardownDone)
	}()

	// The teardown owns the client and must join it; while the deterministic
	// hook is paused, it must not falsely report completion.
	select {
	case <-teardownDone:
		t.Fatal("teardown returned before the accepted client joined")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	select {
	case <-teardownDone:
	case <-time.After(time.Second):
		t.Fatal("teardown hung after releasing endpoint creation gate")
	}

	select {
	case err := <-serveDone:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(time.Second):
		t.Fatal("userspace listener did not stop")
	}
}
