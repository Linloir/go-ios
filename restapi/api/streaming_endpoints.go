package api

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"sync"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/instruments"
	"github.com/danielpaulus/go-ios/ios/ostrace"
	"github.com/danielpaulus/go-ios/ios/syslog"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

func closeStreamOnRequestDone(ctx context.Context, closeFunc func() error) func() {
	done := make(chan struct{})
	watcherDone := make(chan struct{})
	var closeOnce sync.Once
	var cleanupOnce sync.Once
	closeTransport := func() {
		closeOnce.Do(func() { _ = closeFunc() })
	}
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			closeTransport()
		case <-done:
		}
	}()
	return func() {
		cleanupOnce.Do(func() {
			close(done)
			<-watcherDone
			closeTransport()
		})
	}
}

// Notifications uses instruments to get application state change events. It will stream the events as json objects separated by line breaks until it errors out.
// Listen                godoc
// @Summary      uses instruments to get application state change events
// @Description uses instruments to get application state change events
// @Tags         general
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Router       /notifications [get]
func Notifications(c *gin.Context) {
	device := c.MustGet(IOS_KEY).(ios.DeviceEntry)
	listenerFunc, closeFunc, err := instruments.ListenAppStateNotifications(device)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// Gin cannot observe clientGone while listenerFunc is blocked waiting for a
	// device event. Closing the transport wakes it and lets the handler return.
	defer closeStreamOnRequestDone(c.Request.Context(), closeFunc)()
	c.Stream(func(w io.Writer) bool {

		notification, err := listenerFunc()
		if err != nil {
			c.JSON(http.StatusInternalServerError, err)
			return false
		}

		_, err = w.Write([]byte(MustMarshal(notification)))

		if err != nil {
			c.JSON(http.StatusInternalServerError, err)
			return false
		}
		w.Write([]byte("\n"))
		return true
	})

}

// Syslog
// Listen                godoc
// @Summary      Uses SSE to connect to the LISTEN command
// @Description Uses SSE to connect to the LISTEN command
// @Tags         general
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Router       /listen [get]
func Syslog(c *gin.Context) {
	// We are streaming current time to clients in the interval 10 seconds
	log.Info("connect")
	device := c.MustGet(IOS_KEY).(ios.DeviceEntry)
	syslogConnection, err := syslog.New(device)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}
	defer closeStreamOnRequestDone(c.Request.Context(), syslogConnection.Close)()
	c.Stream(func(w io.Writer) bool {
		m, err := syslogConnection.ReadLogMessage()
		if err != nil {
			return false
		}
		// Stream message to client from message channel
		_, err = w.Write([]byte(MustMarshal(m)))
		return err == nil
	})
}

// OsTrace streams structured syslog entries via os_trace_relay with optional device-side PID filtering.
// OsTrace                godoc
// @Summary      Stream structured syslog via os_trace_relay
// @Description  Streams structured syslog entries from the device using os_trace_relay. Supports device-side PID filtering.
// @Tags         general
// @Produce      json
// @Param        pid  query  int  false  "Filter by process ID (-1 for all)"
// @Success      200  {object}  map[string]interface{}
// @Router       /ostrace [get]
func OsTrace(c *gin.Context) {
	device := c.MustGet(IOS_KEY).(ios.DeviceEntry)
	pid := -1
	if pidStr := c.Query("pid"); pidStr != "" {
		var err error
		pid, err = strconv.Atoi(pidStr)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid pid parameter"})
			return
		}
	}
	levelFilter, err := ostrace.ParseLevelFilter(c.Query("level"))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	clientFilter := ostrace.ClientFilter{
		Levels:    levelFilter.ClientLevels,
		Subsystem: c.Query("subsystem"),
		Match:     c.Query("match"),
		Exclude:   c.Query("exclude"),
	}
	conn, err := ostrace.New(device, pid, levelFilter.MessageFilter, levelFilter.StreamFlags)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer closeStreamOnRequestDone(c.Request.Context(), conn.Close)()
	c.Stream(func(w io.Writer) bool {
		entry, err := conn.ReadFilteredEntry(clientFilter)
		if err != nil {
			return false
		}
		if _, err := w.Write([]byte(MustMarshal(entry))); err != nil {
			return false
		}
		_, err = w.Write([]byte("\n"))
		return err == nil
	})
}

// Listen send server side events when devices are plugged in or removed
// Listen                godoc
// @Summary      Uses SSE to connect to the LISTEN command
// @Description Uses SSE to connect to the LISTEN command
// @Tags         general
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Router       /listen [get]
func Listen(c *gin.Context) {
	// We are streaming current time to clients in the interval 10 seconds
	log.Info("connect")
	a, closeFunc, err := ios.Listen()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer closeStreamOnRequestDone(c.Request.Context(), closeFunc)()
	c.Stream(func(w io.Writer) bool {
		l, err := a()
		if err != nil {
			return false
		}
		// Stream message to client from message channel
		_, err = w.Write([]byte(MustMarshal(l)))
		return err == nil
	})
}
