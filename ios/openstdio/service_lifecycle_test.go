package openstdio

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestReadOpenStdIOUUIDCompletesShortReadsAndClearsDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	want := uuid.MustParse("12345678-1234-5678-9abc-def012345678")
	go func() {
		_, _ = server.Write(want[:5])
		_, _ = server.Write(want[5:])
	}()

	got, err := readOpenStdIOUUID(client, time.Second)
	if err != nil {
		t.Fatalf("readOpenStdIOUUID() error = %v", err)
	}
	if got != want {
		t.Fatalf("UUID = %s, want %s", got, want)
	}
	// A cleared setup deadline must not poison normal reads after construction.
	go func() { _, _ = server.Write([]byte{'x'}) }()
	buf := make([]byte, 1)
	if _, err := io.ReadFull(client, buf); err != nil || buf[0] != 'x' {
		t.Fatalf("post-handshake read = %q, %v", buf, err)
	}
}

func TestReadOpenStdIOUUIDTimesOutOnSilentPeer(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	_, err := readOpenStdIOUUID(client, 20*time.Millisecond)
	if err == nil {
		t.Fatal("readOpenStdIOUUID() error = nil, want timeout")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("readOpenStdIOUUID() error = %v, want net timeout", err)
	}
}
