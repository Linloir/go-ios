package xpc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func encodedWrapperWithBodyLength(t *testing.T, bodyLength uint64, body []byte) []byte {
	t.Helper()
	var encoded bytes.Buffer
	if err := binary.Write(&encoded, binary.LittleEndian, wrapperMagic); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&encoded, binary.LittleEndian, wrapperHeader{
		Flags:   AlwaysSetFlag | DataFlag,
		BodyLen: bodyLength,
		MsgId:   1,
	}); err != nil {
		t.Fatal(err)
	}
	encoded.Write(body)
	return encoded.Bytes()
}

func TestDecodeMessageRejectsInvalidBodyLengthsBeforeAllocation(t *testing.T) {
	tests := []struct {
		name       string
		bodyLength uint64
		want       string
	}{
		{name: "smaller than body header", bodyLength: xpcBodyHeaderLength - 1, want: "minimum"},
		{name: "larger than limit", bodyLength: maxXPCBodyLength + 1, want: "exceeds limit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeMessage(bytes.NewReader(encodedWrapperWithBodyLength(t, tt.bodyLength, nil)))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("DecodeMessage() error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

type oneByteReader struct {
	r io.Reader
}

func (r oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.r.Read(p)
}

func TestDecodeMessageReadsFragmentedBodyFully(t *testing.T) {
	var encoded bytes.Buffer
	want := Message{
		Flags: AlwaysSetFlag | DataFlag,
		Body:  map[string]interface{}{"fragmented": "reader"},
		Id:    9,
	}
	if err := EncodeMessage(&encoded, want); err != nil {
		t.Fatalf("EncodeMessage() error = %v", err)
	}
	got, err := DecodeMessage(oneByteReader{r: bytes.NewReader(encoded.Bytes())})
	if err != nil {
		t.Fatalf("DecodeMessage() error = %v", err)
	}
	if got.Body["fragmented"] != "reader" {
		t.Fatalf("decoded body = %#v", got.Body)
	}
	if got.Id != want.Id {
		t.Fatalf("decoded message ID = %d, want %d", got.Id, want.Id)
	}
}

func TestDecodeMessagePreservesEmptyMessageID(t *testing.T) {
	var encoded bytes.Buffer
	want := Message{Flags: InitHandshakeFlag | AlwaysSetFlag, Id: 42}
	if err := EncodeMessage(&encoded, want); err != nil {
		t.Fatalf("EncodeMessage() error = %v", err)
	}
	got, err := DecodeMessage(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatalf("DecodeMessage() error = %v", err)
	}
	if got.Id != want.Id {
		t.Fatalf("decoded message ID = %d, want %d", got.Id, want.Id)
	}
}

func TestDecodeMessageReportsTruncatedBody(t *testing.T) {
	var encoded bytes.Buffer
	if err := EncodeMessage(&encoded, Message{
		Flags: AlwaysSetFlag | DataFlag,
		Body:  map[string]interface{}{"truncated": "body"},
	}); err != nil {
		t.Fatalf("EncodeMessage() error = %v", err)
	}
	data := encoded.Bytes()
	_, err := DecodeMessage(bytes.NewReader(data[:len(data)-1]))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("DecodeMessage() error = %v, want %v", err, io.ErrUnexpectedEOF)
	}
}

func TestDecodeMessageRejectsNestedLengthsThatDoNotFitBody(t *testing.T) {
	tests := []struct {
		name    string
		typeTag xpcType
		length  uint32
		extra   []byte
	}{
		{name: "string", typeTag: stringType, length: ^uint32(0)},
		{name: "data", typeTag: dataType, length: ^uint32(0)},
		{name: "array count", typeTag: arrayType, length: 4, extra: []byte{0xff, 0xff, 0xff, 0xff}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dictionary bytes.Buffer
			if err := binary.Write(&dictionary, binary.LittleEndian, dictionaryType); err != nil {
				t.Fatal(err)
			}
			// Dictionary payload: one entry, padded "k" key, then the
			// deliberately malformed nested object.
			var payload bytes.Buffer
			_ = binary.Write(&payload, binary.LittleEndian, uint32(1))
			payload.Write([]byte{'k', 0, 0, 0})
			_ = binary.Write(&payload, binary.LittleEndian, tt.typeTag)
			_ = binary.Write(&payload, binary.LittleEndian, tt.length)
			payload.Write(tt.extra)
			_ = binary.Write(&dictionary, binary.LittleEndian, uint32(payload.Len()))
			dictionary.Write(payload.Bytes())

			var body bytes.Buffer
			_ = binary.Write(&body, binary.LittleEndian, objectMagic)
			_ = binary.Write(&body, binary.LittleEndian, bodyVersion)
			body.Write(dictionary.Bytes())
			_, err := DecodeMessage(bytes.NewReader(encodedWrapperWithBodyLength(t, uint64(body.Len()), body.Bytes())))
			if err == nil {
				t.Fatal("DecodeMessage() error = nil, want malformed nested length error")
			}
		})
	}
}

type shortWriter struct {
	max int
	buf bytes.Buffer
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > w.max {
		p = p[:w.max]
	}
	return w.buf.Write(p)
}

func TestEncodeMessageWritesAllBytesToShortWriter(t *testing.T) {
	w := &shortWriter{max: 3}
	if err := EncodeMessage(w, Message{
		Flags: AlwaysSetFlag | DataFlag,
		Body:  map[string]interface{}{"short": "writer"},
		Id:    7,
	}); err != nil {
		t.Fatalf("EncodeMessage() error = %v", err)
	}
	decoded, err := DecodeMessage(bytes.NewReader(w.buf.Bytes()))
	if err != nil {
		t.Fatalf("DecodeMessage() error = %v", err)
	}
	if decoded.Body["short"] != "writer" {
		t.Fatalf("decoded body = %#v", decoded.Body)
	}
}

type noProgressWriter struct{}

func (noProgressWriter) Write([]byte) (int, error) { return 0, nil }

func TestEncodeMessageRejectsWriterWithoutProgress(t *testing.T) {
	err := EncodeMessage(noProgressWriter{}, Message{Flags: AlwaysSetFlag})
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("EncodeMessage() error = %v, want %v", err, io.ErrShortWrite)
	}
}
