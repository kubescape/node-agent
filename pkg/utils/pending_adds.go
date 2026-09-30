package utils

import (
	"context"
	"errors"
	"sync"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

// ErrContainerRemoved is the cancellation cause of a registration aborted by
// the container's remove event.
var ErrContainerRemoved = errors.New("container removed")

// PendingAdds tracks in-flight container registrations so the container's
// remove event can abort them. A registration that fails because of that
// abort is expected (the container exited first, see #848), while any other
// failure, including a timeout for a live container, is not. The zero value
// is ready for use.
type PendingAdds struct {
	mu   sync.Mutex
	adds map[string]map[*pendingAdd]struct{}
}

type pendingAdd struct {
	cancel context.CancelCauseFunc
}

// Track registers a registration for key. The returned context is canceled
// with ErrContainerRemoved by a later Cancel(key). Call release once the
// registration settles. Track must run in the add callback itself, not in a
// goroutine it spawns, so a remove callback that follows it always observes
// the registration.
func (p *PendingAdds) Track(key string) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(context.Background())
	add := &pendingAdd{cancel: cancel}
	p.mu.Lock()
	if p.adds == nil {
		p.adds = make(map[string]map[*pendingAdd]struct{})
	}
	if p.adds[key] == nil {
		p.adds[key] = make(map[*pendingAdd]struct{})
	}
	p.adds[key][add] = struct{}{}
	p.mu.Unlock()
	return ctx, func() {
		p.mu.Lock()
		delete(p.adds[key], add)
		if len(p.adds[key]) == 0 {
			delete(p.adds, key)
		}
		p.mu.Unlock()
		cancel(nil)
	}
}

// Cancel aborts every registration tracked for key with ErrContainerRemoved.
// Registrations tracked after this call are not affected, so a readmitted
// container registers normally.
func (p *PendingAdds) Cancel(key string) {
	p.mu.Lock()
	adds := p.adds[key]
	delete(p.adds, key)
	p.mu.Unlock()
	for add := range adds {
		add.cancel(ErrContainerRemoved)
	}
}

// Len returns the number of tracked registrations for key.
func (p *PendingAdds) Len(key string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.adds[key])
}

// RemovedDuringAdd reports whether ctx, or a parent of it, was canceled by
// PendingAdds.Cancel.
func RemovedDuringAdd(ctx context.Context) bool {
	return errors.Is(context.Cause(ctx), ErrContainerRemoved)
}

// AddFailureLogger returns the Debug logger for a registration aborted by the
// container's removal, and the Error logger otherwise. Missing shared data
// alone is no proof of removal: its producer may still be retrying for a live
// container.
func AddFailureLogger(ctx context.Context) func(string, ...helpers.IDetails) {
	if RemovedDuringAdd(ctx) {
		return logger.L().Debug
	}
	return logger.L().Error
}
