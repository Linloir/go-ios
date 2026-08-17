package ios

import (
	"context"
	"io"
	"sync"
)

// contextConnectionGuard closes a live protocol connection when its setup
// context is canceled. Stop synchronizes with an in-flight close callback, so
// callers never hand a connection to another owner while cancellation is still
// able to close it.
type contextConnectionGuard struct {
	stop     func() bool
	done     chan struct{}
	stopOnce sync.Once
	stopped  bool
}

func closeConnectionOnContext(ctx context.Context, conn io.Closer) *contextConnectionGuard {
	if ctx == nil {
		ctx = context.Background()
	}
	done := make(chan struct{})
	guard := &contextConnectionGuard{done: done}
	guard.stop = context.AfterFunc(ctx, func() {
		defer close(done)
		_ = conn.Close()
	})
	return guard
}

// Stop returns true when the cancellation callback was stopped before it ran.
// A false return means cancellation won the race and the connection has been
// closed before Stop returns.
func (g *contextConnectionGuard) Stop() bool {
	if g == nil {
		return true
	}
	g.stopOnce.Do(func() {
		g.stopped = g.stop()
		if !g.stopped {
			<-g.done
		}
	})
	return g.stopped
}
