package tunnel

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

// ipv6HeaderLen is the size of the fixed IPv6 header in bytes. The 16-bit
// payload-length field lives at offset 4..6 and counts every byte after this
// fixed header (including any extension headers).
const ipv6HeaderLen = 40

// framedIPv6Reader turns a raw byte stream that carries back-to-back bare IPv6
// packets into a packet-boundary-preserving reader: every successful Read
// returns exactly one complete IPv6 packet.
//
// The lockdown tunnel is a TCP byte stream, so its Read boundaries do not
// correspond to packet boundaries. gVisor's link endpoint does require one
// packet per Read; without reframing, split or coalesced TCP reads corrupt or
// silently drop traffic.
type framedIPv6Reader struct {
	br *bufio.Reader
}

func newFramedIPv6Reader(r io.Reader) *framedIPv6Reader {
	return &framedIPv6Reader{br: bufio.NewReader(r)}
}

func (r *framedIPv6Reader) Read(p []byte) (int, error) {
	if len(p) < ipv6HeaderLen {
		return 0, fmt.Errorf("framedIPv6Reader: buffer of %d bytes is smaller than the IPv6 header", len(p))
	}
	if _, err := io.ReadFull(r.br, p[:ipv6HeaderLen]); err != nil {
		return 0, fmt.Errorf("framedIPv6Reader: failed to read IPv6 header: %w", err)
	}
	if p[0]>>4 != 6 {
		return 0, fmt.Errorf("framedIPv6Reader: not an IPv6 packet: expected version 6, got %d", p[0]>>4)
	}
	payloadLength := int(binary.BigEndian.Uint16(p[4:6]))
	total := ipv6HeaderLen + payloadLength
	if total > len(p) {
		// Failing tears down the stream instead of returning a partial packet,
		// which would desynchronise every packet that follows it.
		return 0, fmt.Errorf("framedIPv6Reader: packet of %d bytes exceeds buffer of %d bytes", total, len(p))
	}
	if _, err := io.ReadFull(r.br, p[ipv6HeaderLen:total]); err != nil {
		return 0, fmt.Errorf("framedIPv6Reader: failed to read payload of length %d: %w", payloadLength, err)
	}
	return total, nil
}

// framedIPv6Conn reframes reads while writes and Close pass directly through
// to the underlying connection. Outbound writes are already packet-aligned.
type framedIPv6Conn struct {
	io.WriteCloser
	r *framedIPv6Reader
}

// newFramedIPv6Conn must be called only after the tunnel handshake has been
// consumed, so the reader starts exactly on an IPv6 packet boundary.
func newFramedIPv6Conn(conn io.ReadWriteCloser) *framedIPv6Conn {
	return &framedIPv6Conn{
		WriteCloser: conn,
		r:           newFramedIPv6Reader(conn),
	}
}

func (c *framedIPv6Conn) Read(p []byte) (int, error) { return c.r.Read(p) }
