package tunnel

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const coreTunnelTestMagic = "CDTunnel"

type coreTunnelFramingTestStream struct {
	reader     io.Reader
	written    bytes.Buffer
	writeLimit int
	writeCalls int
	writeErrAt int
	writeErr   error
	zeroWrite  bool
}

func (s *coreTunnelFramingTestStream) Read(data []byte) (int, error) {
	return s.reader.Read(data)
}

func (s *coreTunnelFramingTestStream) Write(data []byte) (int, error) {
	s.writeCalls++
	if s.zeroWrite {
		return 0, nil
	}
	n := len(data)
	if s.writeLimit > 0 && n > s.writeLimit {
		n = s.writeLimit
	}
	_, _ = s.written.Write(data[:n])
	if s.writeErrAt == s.writeCalls {
		return n, s.writeErr
	}
	return n, nil
}

func (*coreTunnelFramingTestStream) Close() error { return nil }

func coreTunnelTestFrame(magic string, declaredLength int, body []byte) []byte {
	frame := make([]byte, len(magic)+2+len(body))
	copy(frame, magic)
	binary.BigEndian.PutUint16(frame[len(magic):], uint16(declaredLength))
	copy(frame[len(magic)+2:], body)
	return frame
}

func TestExchangeCoreTunnelParametersHandlesFragmentedResponseAndShortWrites(t *testing.T) {
	body, err := json.Marshal(map[string]interface{}{
		"serverAddress": "fd00::1234",
		"serverRSDPort": 62078,
		"clientParameters": map[string]interface{}{
			"address": "fd00::5678",
			"netmask": "ffff:ffff:ffff:ffff::",
			"mtu":     1280,
		},
		// Keep the body over 255 bytes to prove that the length is uint16 rather
		// than the historical one-byte implementation.
		"ignoredPadding": strings.Repeat("x", 300),
	})
	require.NoError(t, err)
	require.Greater(t, len(body), 255)
	response := coreTunnelTestFrame(coreTunnelTestMagic, len(body), body)
	stream := &coreTunnelFramingTestStream{
		reader:     iotest.OneByteReader(bytes.NewReader(response)),
		writeLimit: 3,
	}

	parameters, err := exchangeCoreTunnelParameters(stream)
	require.NoError(t, err)
	assert.Equal(t, "fd00::1234", parameters.ServerAddress)
	assert.Equal(t, uint64(62078), parameters.ServerRSDPort)
	assert.Equal(t, "fd00::5678", parameters.ClientParameters.Address)
	assert.Equal(t, "ffff:ffff:ffff:ffff::", parameters.ClientParameters.Netmask)
	assert.Equal(t, uint64(1280), parameters.ClientParameters.Mtu)
	assert.Greater(t, stream.writeCalls, 1, "request must survive a short-writing stream")

	request := stream.written.Bytes()
	require.GreaterOrEqual(t, len(request), len(coreTunnelTestMagic)+2)
	assert.Equal(t, coreTunnelTestMagic, string(request[:len(coreTunnelTestMagic)]))
	requestLength := int(binary.BigEndian.Uint16(request[len(coreTunnelTestMagic):]))
	require.Equal(t, len(request)-len(coreTunnelTestMagic)-2, requestLength)
	var decodedRequest struct {
		Type string `json:"type"`
		Mtu  int    `json:"mtu"`
	}
	require.NoError(t, json.Unmarshal(request[len(coreTunnelTestMagic)+2:], &decodedRequest))
	assert.Equal(t, "clientHandshakeRequest", decodedRequest.Type)
	assert.Equal(t, 1280, decodedRequest.Mtu)
}

func TestExchangeCoreTunnelParametersRejectsMalformedFrames(t *testing.T) {
	validBody := []byte(`{"serverAddress":"fd00::1","serverRSDPort":62078}`)
	tests := []struct {
		name     string
		response []byte
		contains string
	}{
		{
			name:     "truncated header",
			response: []byte("CDTunnel"),
			contains: "response header",
		},
		{
			name:     "invalid magic",
			response: coreTunnelTestFrame("XDTunnel", len(validBody), validBody),
			contains: "response magic",
		},
		{
			name:     "truncated body",
			response: coreTunnelTestFrame(coreTunnelTestMagic, len(validBody)+7, validBody),
			contains: "response body",
		},
		{
			name:     "invalid JSON",
			response: coreTunnelTestFrame(coreTunnelTestMagic, 1, []byte("{")),
			contains: "decode CoreDevice tunnel response",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stream := &coreTunnelFramingTestStream{reader: bytes.NewReader(test.response)}
			_, err := exchangeCoreTunnelParameters(stream)
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.contains)
		})
	}
}

func TestExchangeCoreTunnelParametersPropagatesWriteFailures(t *testing.T) {
	t.Run("partial write with error", func(t *testing.T) {
		wantErr := errors.New("write failed")
		stream := &coreTunnelFramingTestStream{
			reader:     bytes.NewReader(nil),
			writeLimit: 4,
			writeErrAt: 2,
			writeErr:   wantErr,
		}
		_, err := exchangeCoreTunnelParameters(stream)
		require.Error(t, err)
		assert.ErrorIs(t, err, wantErr)
		assert.Equal(t, 2, stream.writeCalls)
	})

	t.Run("zero progress", func(t *testing.T) {
		stream := &coreTunnelFramingTestStream{reader: bytes.NewReader(nil), zeroWrite: true}
		_, err := exchangeCoreTunnelParameters(stream)
		require.Error(t, err)
		assert.ErrorIs(t, err, io.ErrNoProgress)
		assert.Equal(t, 1, stream.writeCalls)
	})
}
