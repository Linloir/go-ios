package instruments

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image/jpeg"
	"image/png"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	dtx "github.com/danielpaulus/go-ios/ios/dtx_codec"
	log "github.com/sirupsen/logrus"
)

const screenshotServiceName string = "com.apple.instruments.server.services.screenshot"

type ScreenshotService struct {
	channel *dtx.Channel
	conn    *dtx.Connection
}

func NewScreenshotService(device ios.DeviceEntry) (*ScreenshotService, error) {
	dtxConn, err := connectInstruments(device)
	if err != nil {
		return nil, err
	}
	processControlChannel, err := dtxConn.RequestChannelIdentifierWithError(screenshotServiceName, loggingDispatcher{dtxConn})
	if err != nil {
		_ = dtxConn.Close()
		return nil, fmt.Errorf("request screenshot channel: %w", err)
	}
	return &ScreenshotService{channel: processControlChannel, conn: dtxConn}, nil
}

func (d *ScreenshotService) Close() {
	d.conn.Close()
}

func (d *ScreenshotService) TakeScreenshot() ([]byte, error) {
	msg, err := d.channel.MethodCall("takeScreenshot")
	if err != nil {
		return nil, fmt.Errorf("TakeScreenshot: %w", err)
	}
	if len(msg.Payload) == 0 {
		return nil, errors.New("TakeScreenshot: empty response payload")
	}
	imageBytes, ok := msg.Payload[0].([]byte)
	if !ok {
		return nil, fmt.Errorf("TakeScreenshot: expected []byte payload, got %T", msg.Payload[0])
	}
	return imageBytes, nil
}

type mjpegStreamer struct {
	consumers       sync.Map
	conversionQueue chan []byte
}

func newMJPEGStreamer() *mjpegStreamer {
	return &mjpegStreamer{conversionQueue: make(chan []byte, 20)}
}

// StartMJPEGStreamingServer starts an MJPEG screenshot stream.
func StartMJPEGStreamingServer(device ios.DeviceEntry, port string) error {
	screenshotService, err := NewScreenshotService(device)
	if err != nil {
		return err
	}
	defer screenshotService.Close()

	location := net.JoinHostPort("0.0.0.0", port)
	listener, err := net.Listen("tcp", location)
	if err != nil {
		return fmt.Errorf("StartMJPEGStreamingServer: listen on %s: %w", location, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	streamer := newMJPEGStreamer()
	go streamer.startConversionQueue(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/", streamer.mjpegHandler)
	server := &http.Server{Handler: mux}
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Serve(listener) }()
	screenshotErr := make(chan error, 1)
	go func() { screenshotErr <- streamer.startScreenshotting(ctx, screenshotService) }()

	log.WithFields(log.Fields{"host": "0.0.0.0", "port": port}).Infof("starting server, open your browser here: http://%s/", location)
	select {
	case err := <-screenshotErr:
		cancel()
		_ = server.Close()
		if err != nil {
			return fmt.Errorf("StartMJPEGStreamingServer: %w", err)
		}
		return nil
	case err := <-serverErr:
		cancel()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("StartMJPEGStreamingServer: %w", err)
	}
}

func (s *mjpegStreamer) startConversionQueue(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case pngBytes := <-s.conversionQueue:
			start := time.Now()
			jpgBytes, err := convertPNGToJPEG(pngBytes, 80)
			if err != nil {
				log.Warnf("failed converting screenshot to JPEG: %v", err)
				continue
			}
			log.Debugf("conversion took %fs", time.Since(start).Seconds())
			s.broadcast(jpgBytes)
		}
	}
}

func convertPNGToJPEG(pngBytes []byte, quality int) ([]byte, error) {
	img, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		return nil, fmt.Errorf("decode PNG: %w", err)
	}
	var result bytes.Buffer
	if err := jpeg.Encode(&result, img, &jpeg.Options{Quality: quality}); err != nil {
		return nil, fmt.Errorf("encode JPEG: %w", err)
	}
	return result.Bytes(), nil
}

func (s *mjpegStreamer) broadcast(frame []byte) {
	s.consumers.Range(func(_, value interface{}) bool {
		consumer := value.(chan []byte)
		// Each consumer holds at most the newest pending frame. A slow client
		// must not spawn goroutines or apply backpressure to capture/conversion.
		select {
		case consumer <- frame:
		default:
			select {
			case <-consumer:
			default:
			}
			select {
			case consumer <- frame:
			default:
			}
		}
		return true
	})
}

func (s *mjpegStreamer) startScreenshotting(ctx context.Context, conn *ScreenshotService) error {
	for {
		start := time.Now()
		pngBytes, err := conn.TakeScreenshot()
		if err != nil {
			return fmt.Errorf("screenshot failed: %w", err)
		}
		log.Debugf("shot took %fs", time.Since(start).Seconds())
		select {
		case s.conversionQueue <- pngBytes:
		case <-ctx.Done():
			return nil
		}
	}
}

const (
	mjpegFrameFooter = "\r\n\r\n"
	mjpegFrameHeader = "--BoundaryString\r\nContent-Type: image/jpeg\r\nContent-Length: %d\r\n\r\n"
)

func (s *mjpegStreamer) mjpegHandler(w http.ResponseWriter, r *http.Request) {
	log.Infof("starting mjpeg stream for new client")
	frames := make(chan []byte, 1)
	s.consumers.Store(r, frames)
	defer func() {
		s.consumers.Delete(r)
		log.Info("client disconnected")
	}()

	w.Header().Set("Server", "go-ios-screenshotr-mjpeg-stream")
	w.Header().Set("Connection", "Close")
	w.Header().Set("Content-Type", "multipart/x-mixed-replace; boundary=BoundaryString")
	w.Header().Set("Max-Age", "0")
	w.Header().Set("Expires", "0")
	w.Header().Set("Cache-Control", "no-cache, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	for {
		select {
		case <-r.Context().Done():
			return
		case jpg := <-frames:
			if _, err := io.WriteString(w, fmt.Sprintf(mjpegFrameHeader, len(jpg))); err != nil {
				return
			}
			if _, err := w.Write(jpg); err != nil {
				return
			}
			if _, err := io.WriteString(w, mjpegFrameFooter); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
	}
}
