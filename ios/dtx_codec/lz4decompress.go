package dtx

import (
	"encoding/binary"
	"fmt"

	"github.com/pierrec/lz4"
)

const bv41 = 0x62763431

// https://discuss.appium.io/t/how-to-parse-trace-file-to-get-cpu-performance-usage-data-for-ios-apps/35334/2
func Decompress(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("LZ4 DTX payload is missing its size header")
	}
	if len(data) > maxDTXMessageLength {
		return nil, fmt.Errorf("LZ4 DTX payload length %d exceeds limit %d", len(data), maxDTXMessageLength)
	}
	// no idea what the first four bytes mean
	totalUncompressedSize := binary.LittleEndian.Uint32(data)
	if totalUncompressedSize > maxDTXMessageLength {
		return nil, fmt.Errorf("LZ4 DTX uncompressed length %d exceeds limit %d", totalUncompressedSize, maxDTXMessageLength)
	}
	data = data[4:]

	compressedAgg := make([]byte, 0)
	chunks := 0
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, fmt.Errorf("truncated LZ4 DTX chunk marker")
		}
		if binary.BigEndian.Uint32(data) != bv41 {
			break
		}
		if len(data) < 12 {
			return nil, fmt.Errorf("truncated LZ4 DTX chunk header")
		}
		// uncompressedSize := binary.LittleEndian.Uint32(data[4:])
		compressedSize := binary.LittleEndian.Uint32(data[8:])
		if uint64(compressedSize) > uint64(len(data)-12) {
			return nil, fmt.Errorf("LZ4 DTX chunk length %d exceeds remaining payload %d", compressedSize, len(data)-12)
		}
		chunkEnd := 12 + int(compressedSize)
		chunk := data[12:chunkEnd]
		// log.Infof("chunk: %x", chunk)
		data = data[chunkEnd:]

		if len(compressedAgg) > maxDTXMessageLength-len(chunk) {
			return nil, fmt.Errorf("LZ4 DTX compressed chunks exceed limit %d", maxDTXMessageLength)
		}
		compressedAgg = append(compressedAgg, chunk...)
		chunks++
	}
	if chunks == 0 {
		return nil, fmt.Errorf("LZ4 DTX payload contains no chunks")
	}
	uncompressedData := make([]byte, int(totalUncompressedSize))
	n, err := lz4.UncompressBlock(compressedAgg, uncompressedData)
	if err != nil {
		return []byte{}, err
	}
	if n != len(uncompressedData) {
		return nil, fmt.Errorf("LZ4 DTX decompressed length %d does not match declared length %d", n, totalUncompressedSize)
	}
	// log.Infof("uncompressed lz4 data of %d bytes", len(uncompressedData[:n]))
	return uncompressedData[:n], nil
}
