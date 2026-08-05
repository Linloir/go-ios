package tunnel

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"testing/iotest"
)

func buildIPv6Packet(payload []byte) []byte {
	pkt := make([]byte, ipv6HeaderLen+len(payload))
	pkt[0] = 6 << 4
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(payload)))
	copy(pkt[ipv6HeaderLen:], payload)
	return pkt
}

func readOne(t *testing.T, r io.Reader, bufSize int) []byte {
	t.Helper()
	buf := make([]byte, bufSize)
	n, err := r.Read(buf)
	if err != nil {
		t.Fatalf("Read returned error: %v", err)
	}
	return buf[:n]
}

func TestFramedIPv6ReaderSinglePacket(t *testing.T) {
	pkt := buildIPv6Packet([]byte("hello world"))
	r := newFramedIPv6Reader(bytes.NewReader(pkt))

	if got := readOne(t, r, 1500); !bytes.Equal(got, pkt) {
		t.Fatalf("got %d bytes, want %d (%x vs %x)", len(got), len(pkt), got, pkt)
	}
}

func TestFramedIPv6ReaderCoalesced(t *testing.T) {
	p1 := buildIPv6Packet([]byte("first packet payload"))
	p2 := buildIPv6Packet([]byte("second"))
	stream := append(append([]byte{}, p1...), p2...)
	r := newFramedIPv6Reader(bytes.NewReader(stream))

	if got := readOne(t, r, 1500); !bytes.Equal(got, p1) {
		t.Fatalf("packet 1: got %x, want %x", got, p1)
	}
	if got := readOne(t, r, 1500); !bytes.Equal(got, p2) {
		t.Fatalf("packet 2: got %x, want %x", got, p2)
	}
}

func TestFramedIPv6ReaderSplit(t *testing.T) {
	p1 := buildIPv6Packet(bytes.Repeat([]byte{0xAB}, 200))
	p2 := buildIPv6Packet(bytes.Repeat([]byte{0xCD}, 37))
	stream := append(append([]byte{}, p1...), p2...)
	r := newFramedIPv6Reader(iotest.OneByteReader(bytes.NewReader(stream)))

	if got := readOne(t, r, 1500); !bytes.Equal(got, p1) {
		t.Fatalf("packet 1: got %d bytes, want %d", len(got), len(p1))
	}
	if got := readOne(t, r, 1500); !bytes.Equal(got, p2) {
		t.Fatalf("packet 2: got %d bytes, want %d", len(got), len(p2))
	}
}

func TestFramedIPv6ReaderRejectsInvalidInput(t *testing.T) {
	t.Run("not IPv6", func(t *testing.T) {
		pkt := buildIPv6Packet([]byte("x"))
		pkt[0] = 4 << 4
		if _, err := newFramedIPv6Reader(bytes.NewReader(pkt)).Read(make([]byte, 1500)); err == nil {
			t.Fatal("expected an error for a non-IPv6 packet")
		}
	})

	t.Run("buffer smaller than header", func(t *testing.T) {
		r := newFramedIPv6Reader(bytes.NewReader(buildIPv6Packet([]byte("data"))))
		if _, err := r.Read(make([]byte, ipv6HeaderLen-1)); err == nil {
			t.Fatal("expected an error for a short buffer")
		}
	})

	t.Run("packet exceeds buffer", func(t *testing.T) {
		pkt := buildIPv6Packet(bytes.Repeat([]byte{0x01}, 100))
		if _, err := newFramedIPv6Reader(bytes.NewReader(pkt)).Read(make([]byte, 100)); err == nil {
			t.Fatal("expected an error for a packet larger than the buffer")
		}
	})

	t.Run("EOF", func(t *testing.T) {
		if _, err := newFramedIPv6Reader(bytes.NewReader(nil)).Read(make([]byte, 1500)); err == nil {
			t.Fatal("expected an error on EOF")
		}
	})
}

func TestFramedIPv6ConnWritePassthrough(t *testing.T) {
	var written bytes.Buffer
	rwc := &framingReadWriteCloser{
		Reader: bytes.NewReader(buildIPv6Packet([]byte("in"))),
		Writer: &written,
	}
	c := newFramedIPv6Conn(rwc)
	payload := []byte("outbound packet bytes")
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if !bytes.Equal(written.Bytes(), payload) {
		t.Fatalf("write passthrough: got %x, want %x", written.Bytes(), payload)
	}
}

type framingReadWriteCloser struct {
	io.Reader
	io.Writer
}

func (framingReadWriteCloser) Close() error { return nil }
