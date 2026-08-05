package forward

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestForwardListenAddressIsLoopback(t *testing.T) {
	host, port, err := net.SplitHostPort(forwardListenAddress(12345))
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", host)
	assert.Equal(t, "12345", port)
	assert.True(t, net.ParseIP(host).IsLoopback())
}

func TestConnListenerCloseIsIdempotent(t *testing.T) {
	wantErr := errors.New("close failed")
	listener := &stubListener{closeErr: wantErr}
	connListener := &ConnListener{listener: listener, quit: make(chan struct{})}

	assert.ErrorIs(t, connListener.Close(), wantErr)
	assert.ErrorIs(t, connListener.Close(), wantErr)
	assert.Equal(t, int64(1), listener.closeCalls.Load())
	select {
	case <-connListener.quit:
	default:
		t.Fatal("quit channel was not closed")
	}
}

type stubListener struct {
	closeCalls atomic.Int64
	closeErr   error
}

func (*stubListener) Accept() (net.Conn, error) { return nil, errors.New("not implemented") }
func (l *stubListener) Close() error {
	l.closeCalls.Add(1)
	return l.closeErr
}
func (*stubListener) Addr() net.Addr { return stubAddr("stub") }

type stubAddr string

func (a stubAddr) Network() string { return string(a) }
func (a stubAddr) String() string  { return string(a) }
