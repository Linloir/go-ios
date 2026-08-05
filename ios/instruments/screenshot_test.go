package instruments

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertPNGToJPEGProducesCompleteImage(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	img.Set(1, 0, color.RGBA{G: 255, A: 255})
	var source bytes.Buffer
	require.NoError(t, png.Encode(&source, img))

	got, err := convertPNGToJPEG(source.Bytes(), 80)
	require.NoError(t, err)
	assert.NotEmpty(t, got)
	_, err = jpeg.Decode(bytes.NewReader(got))
	require.NoError(t, err)
}

func TestMJPEGBroadcastDoesNotBlockSlowConsumer(t *testing.T) {
	streamer := newMJPEGStreamer()
	consumer := make(chan []byte, 1)
	streamer.consumers.Store("slow", consumer)
	streamer.broadcast([]byte("old"))

	done := make(chan struct{})
	go func() {
		streamer.broadcast([]byte("new"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("broadcast blocked on slow consumer")
	}
	assert.Equal(t, []byte("new"), <-consumer)
}
