package dtx

import (
	"encoding/binary"
	"testing"
)

func TestDecompressRejectsMalformedPeerLengths(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "missing_size", data: []byte{1, 2, 3}},
		{name: "missing_chunks", data: make([]byte, 4)},
		{name: "truncated_marker", data: append(make([]byte, 4), 1)},
		{name: "truncated_chunk_header", data: append(make([]byte, 4), []byte("bv41")...)},
	}

	oversized := make([]byte, 4)
	binary.LittleEndian.PutUint32(oversized, maxDTXMessageLength+1)
	tests = append(tests, struct {
		name string
		data []byte
	}{name: "oversized_output", data: oversized})

	badChunk := make([]byte, 16)
	binary.LittleEndian.PutUint32(badChunk, 8)
	binary.BigEndian.PutUint32(badChunk[4:], bv41)
	binary.LittleEndian.PutUint32(badChunk[12:], 5)
	tests = append(tests, struct {
		name string
		data []byte
	}{name: "chunk_exceeds_input", data: badChunk})

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := Decompress(testCase.data); err == nil {
				t.Fatal("Decompress() error = nil, want malformed input rejection")
			}
		})
	}
}
