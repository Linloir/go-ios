package api

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestCloseStreamOnRequestDoneClosesOnceOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	closed := make(chan struct{})
	cleanup := closeStreamOnRequestDone(ctx, func() error {
		if calls.Add(1) == 1 {
			close(closed)
		}
		return nil
	})
	cancel()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("request cancellation did not close stream transport")
	}
	cleanup()
	if got := calls.Load(); got != 1 {
		t.Fatalf("close calls = %d, want 1", got)
	}
}

func TestCloseStreamOnRequestDoneNormalCleanupStopsWatcher(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	cleanup := closeStreamOnRequestDone(ctx, func() error {
		calls.Add(1)
		return nil
	})
	cleanup()
	cancel()
	if got := calls.Load(); got != 1 {
		t.Fatalf("close calls = %d, want 1", got)
	}
}
