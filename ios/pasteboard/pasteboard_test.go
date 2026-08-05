package pasteboard

import (
	"bytes"
	"testing"

	"github.com/danielpaulus/go-ios/ios/xpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildSetTextRequest(t *testing.T) {
	request := buildSetTextRequest("clipboard text")
	assert.Equal(t, pasteboardCommandSet, request["command"])
	assert.Equal(t, GeneralPasteboard, request["pasteboardName"])
	assert.Contains(t, request, "sourceMetadata")
	assert.Nil(t, request["sourceMetadata"])

	items, ok := request["items"].([]interface{})
	require.True(t, ok)
	require.Len(t, items, 1)
	item, ok := items[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, []interface{}{UTIUTF8PlainText, UTIPlainText, UTIText}, item["types"])

	data, ok := item["data"].(map[string]interface{})
	require.True(t, ok)
	for _, uti := range textUTIs {
		datum, ok := data[uti].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, []byte("clipboard text"), datum["data"])
	}
}

func TestBuildPullRequest(t *testing.T) {
	request := buildPullRequest()
	assert.Equal(t, pasteboardCommandPull, request["command"])
	assert.Equal(t, GeneralPasteboard, request["pasteboardName"])
	assert.Equal(t, map[string]interface{}{
		"allResolved": map[string]interface{}{},
	}, request["dataPolicy"])
}

func TestPasteboardRequestsXPCRoundTrip(t *testing.T) {
	requests := []map[string]interface{}{
		buildSetTextRequest("clipboard text"),
		buildPullRequest(),
	}
	for _, request := range requests {
		var encoded bytes.Buffer
		err := xpc.EncodeMessage(&encoded, xpc.Message{
			Flags: xpc.AlwaysSetFlag | xpc.DataFlag | xpc.HeartbeatRequestFlag,
			Body:  request,
			Id:    1,
		})
		require.NoError(t, err)
		decoded, err := xpc.DecodeMessage(&encoded)
		require.NoError(t, err)
		assert.Equal(t, request, decoded.Body)
	}
}

func TestSnapshotText(t *testing.T) {
	tests := []struct {
		name  string
		reply map[string]interface{}
		want  string
		ok    bool
	}{
		{
			name: "nested snapshot and preferred UTI",
			reply: map[string]interface{}{
				"pasteboard": snapshotWithData(map[string]interface{}{
					UTIText:          map[string]interface{}{"data": []byte("generic")},
					UTIUTF8PlainText: map[string]interface{}{"data": []byte("preferred")},
				}),
			},
			want: "preferred",
			ok:   true,
		},
		{
			name: "bare snapshot and fallback UTI",
			reply: snapshotWithData(map[string]interface{}{
				UTIPlainText: map[string]interface{}{"data": []byte("fallback")},
			}),
			want: "fallback",
			ok:   true,
		},
		{
			name: "promise without inline data",
			reply: snapshotWithData(map[string]interface{}{
				UTIUTF8PlainText: map[string]interface{}{"isPromised": true},
			}),
		},
		{
			name:  "malformed snapshot",
			reply: map[string]interface{}{"items": "not an array"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := snapshotText(test.reply)
			assert.Equal(t, test.want, got)
			assert.Equal(t, test.ok, ok)
		})
	}
}

func snapshotWithData(data map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"items": []interface{}{
			map[string]interface{}{"data": data},
		},
	}
}
