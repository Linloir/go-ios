package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
)

// tunnelRuntime owns the non-serializable lifetime of a published Tunnel.
// Any critical worker returning tears down the whole generation; Close then
// waits until every worker has joined. Tunnel values are copied by the manager,
// so all mutable lifetime state deliberately lives behind this pointer.
type tunnelRuntime struct {
	ctx    context.Context
	cancel context.CancelFunc

	closeResources func() error
	stopOnce       sync.Once
	wg             sync.WaitGroup
	done           chan struct{}

	mu             sync.RWMutex
	stopping       bool
	terminationErr error
	closeErr       error
}

type tunnelRuntimeWorker struct {
	name string
	run  func(context.Context) error
}

func newTunnelRuntime(parent context.Context, closeResources func() error, workers ...tunnelRuntimeWorker) *tunnelRuntime {
	if parent == nil {
		parent = context.Background()
	}
	// Tunnel startup is commonly bounded by a short context. The established
	// underlay must survive that startup deadline and is stopped explicitly by
	// its runtime instead.
	ctx, cancel := context.WithCancel(context.WithoutCancel(parent))
	runtime := &tunnelRuntime{
		ctx:            ctx,
		cancel:         cancel,
		closeResources: closeResources,
		done:           make(chan struct{}),
	}

	runtime.wg.Add(len(workers))
	for _, worker := range workers {
		worker := worker
		go runtime.runWorker(worker)
	}
	go func() {
		runtime.wg.Wait()
		close(runtime.done)
	}()
	return runtime
}

func (r *tunnelRuntime) runWorker(worker tunnelRuntimeWorker) {
	defer r.wg.Done()
	err := worker.run(r.ctx)
	if !r.alive() {
		return
	}
	if err == nil {
		err = errors.New("worker stopped unexpectedly")
	}
	slog.Error("tunnel underlay worker stopped", "worker", worker.name, "err", err)
	r.stop(fmt.Errorf("%s: %w", worker.name, err))
}

// stop initiates teardown exactly once. The first critical worker failure is
// retained as the runtime error; an explicit Close supplies a nil cause.
func (r *tunnelRuntime) stop(cause error) {
	r.stopOnce.Do(func() {
		r.mu.Lock()
		r.stopping = true
		r.terminationErr = cause
		r.mu.Unlock()

		r.cancel()
		var closeErr error
		if r.closeResources != nil {
			closeErr = r.closeResources()
		}
		r.mu.Lock()
		r.closeErr = closeErr
		r.mu.Unlock()
	})
}

func (r *tunnelRuntime) closeAndWait() error {
	if r == nil {
		return nil
	}
	r.stop(nil)
	<-r.done
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.closeErr
}

func (r *tunnelRuntime) alive() bool {
	if r == nil {
		return true
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return !r.stopping
}

func (r *tunnelRuntime) err() error {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return errors.Join(r.terminationErr, r.closeErr)
}
