package igbackend

import (
	"context"
	"sync"
	"time"
)

// evidenceContext is owned solely by the provider. Containerd readers and gRPC
// may retain it after Evidence returns, so it must not reference the SDK caller,
// its values, the bridge, or the finish closure. Each observation gets a new one.
type evidenceContext struct {
	deadline    time.Time
	hasDeadline bool
	done        chan struct{}
	terminal    sync.Once
	err         error // immutable after done closes
}

func (c *evidenceContext) Deadline() (time.Time, bool) { return c.deadline, c.hasDeadline }
func (c *evidenceContext) Done() <-chan struct{}       { return c.done }
func (c *evidenceContext) Value(any) any               { return nil }
func (c *evidenceContext) Err() error {
	select {
	case <-c.done:
		return c.err
	default:
		return nil
	}
}
func (c *evidenceContext) cancel(err error) {
	// Context.Err has only these two terminal values. Do not retain an arbitrary
	// caller error graph, even if a nonconforming Context supplies one.
	terminal := context.Canceled
	if err == context.DeadlineExceeded {
		terminal = context.DeadlineExceeded
	}
	c.terminal.Do(func() { c.err = terminal; close(c.done) })
}

// No independent deadline timer races the caller's committed cancellation
// reason. Copy deadline metadata for downstream RPC deadlines, and relay the
// caller's authoritative Done/Err (including already-canceled callers).
// finish cancels the provider context and joins all bridge access to the caller;
// it does NOT join containerd/gRPC's asynchronous tails or bound their memory.
func newEvidenceContext(caller context.Context) (context.Context, func()) {
	deadline, hasDeadline := caller.Deadline()
	if hasDeadline {
		// A shallow time.Time copy can retain an arbitrarily large caller-owned
		// Location. UTC preserves the absolute instant without that reference.
		// It strips monotonic metadata: downstream deadline calculations use
		// wall time, not exact monotonic equivalence. Caller Done/Err remains
		// authoritative through the joined bridge below.
		deadline = deadline.UTC()
	} else {
		deadline = time.Time{}
	}
	owned := &evidenceContext{deadline: deadline, hasDeadline: hasDeadline, done: make(chan struct{})}
	callerDone := caller.Done()
	if err := caller.Err(); err != nil {
		owned.cancel(err)
	}
	stop, joined := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-callerDone:
			owned.cancel(caller.Err())
		case <-stop:
		}
	}()
	var once sync.Once
	finish := func() {
		once.Do(func() {
			// Observe an already-committed deadline/cancel even if the bridge has not
			// run yet. Finishing a still-live observation is our own cancellation.
			owned.cancel(caller.Err())
			close(stop)
		})
		<-joined
	}
	return owned, finish
}
