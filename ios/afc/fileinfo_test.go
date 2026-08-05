package afc

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseFileInfoModTime(t *testing.T) {
	const modificationNanoseconds = int64(1_700_000_000_123_456_789)
	const birthNanoseconds = int64(1_699_000_000_123_456_789)
	payload := nullSeparated(
		"st_ifmt", "S_IFMT",
		"st_size", "42",
		"st_mode", "100644",
		"st_nlink", "3",
		"st_birthtime", "1699000000123456789",
		"st_mtime", "1700000000123456789",
		"st_linktarget", "/target",
	)

	info := parseFileInfo("/Documents/example.txt", payload)
	assert.Equal(t, "example.txt", info.Name)
	assert.Equal(t, S_IFMT, info.Type)
	assert.Equal(t, int64(42), info.Size)
	assert.Equal(t, uint32(0o100644), info.Mode)
	assert.Equal(t, "3", info.NLink)
	assert.Equal(t, "/target", info.LinkTarget)
	assert.Equal(t, time.Unix(0, birthNanoseconds), info.BirthTime())
	assert.Equal(t, time.Unix(0, modificationNanoseconds), info.ModTime())
}

func TestParseFileInfoMissingOrInvalidModTime(t *testing.T) {
	assert.True(t, parseFileInfo("file", nullSeparated("st_size", "1")).ModTime().IsZero())
	assert.True(t, parseFileInfo("file", nullSeparated("st_mtime", "invalid")).ModTime().IsZero())
	assert.True(t, parseFileInfo("file", nullSeparated("st_birthtime", "invalid")).BirthTime().IsZero())
}

func nullSeparated(values ...string) []byte {
	parts := make([][]byte, 0, len(values)+1)
	for _, value := range values {
		parts = append(parts, []byte(value))
	}
	parts = append(parts, nil)
	return bytes.Join(parts, []byte{0})
}
