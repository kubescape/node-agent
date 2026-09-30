package utils

import (
	"context"
	"errors"
	"sync"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

// ErrContainerRemoved is the cancel cause when a remove event aborts a registration.
var ErrContainerRemoved = errors.New("container removed")

// PendingAdds tracks in-flight registrations so a remove event can abort them.
// A failure from that abort is expected: the container exited first (#848).
// Any other failure is not.
// The zero value is ready for use.
type PendingAdds struct {
	mu   sync.Mutex
	adds map[string]map[*pendingAdd]struct{}
}

type pendingAdd struct {
	cancel context.CancelCauseFunc
}

// Track registers a registration for key.
// A later Cancel(key) cancels the returned context with ErrContainerRemoved.
// Call release once the registration settles.
// Call Track in the add callback itself, not in a spawned goroutine,
// so the following remove callback always sees it.
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

// Cancel aborts every registration tracked for key.
// Later Track calls are not affected, so readmission works.
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

// RemovedDuringAdd reports whether PendingAdds.Cancel canceled ctx or a parent.
func RemovedDuringAdd(ctx context.Context) bool {
	return errors.Is(context.Cause(ctx), ErrContainerRemoved)
}

// AddFailureLogger returns Debug if removal aborted the registration, else Error.
// Missing shared data alone is no proof of removal:
// its producer may still be retrying for a live container.
func AddFailureLogger(ctx context.Context) func(string, ...helpers.IDetails) {
	if RemovedDuringAdd(ctx) {
		return logger.L().Debug
	}
	return logger.L().Error
}
