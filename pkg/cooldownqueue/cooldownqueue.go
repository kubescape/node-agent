package cooldownqueue

import (
	"sync/atomic"
	"time"

	"istio.io/pkg/cache"
)

const (
	DefaultExpiration = 5 * time.Second
	EvictionInterval  = 1 * time.Second
)

// CooldownQueue is a queue that lets clients put events into it with a cooldown
//
// When a client puts an event into a queue, it waits for a cooldown period before
// the event is forwarded to the consumer. If an event for the same key is put into the queue
// again before the cooldown period is over, the event is overridden and the cooldown period is reset.
//
// Concurrency design: the TTL-cache evicter goroutine (istio.io/pkg/cache) cannot be
// stopped synchronously, so we must never close the channel it sends to. Instead a
// relay goroutine owns the consumer-facing channel (resultChan) and closes it only
// after the done signal is received. The intermediate (innerChan) is never closed,
// eliminating any "send on closed channel" panic during shutdown.
type CooldownQueue[T any] struct {
	// closed is set atomically to true when Stop() is called, preventing further
	// Enqueue operations and signalling the relay goroutine via done.
	closed     atomic.Bool
	seenEvents cache.ExpiringCache
	innerChan  chan T   // written only by the eviction callback; never closed
	resultChan <-chan T // closed by the relay goroutine when done is signalled
	done       chan struct{}
}

// NewCooldownQueue returns a new Cooldown Queue
func NewCooldownQueue[T any](cooldown time.Duration, evictionInterval time.Duration) *CooldownQueue[T] {
	// intermediate receives evicted items from the TTL-cache callback.
	// It is NEVER closed so the callback can never panic with "send on closed channel".
	intermediate := make(chan T)
	// result is the consumer-facing channel; it is closed by the relay goroutine
	// once Stop() signals done, unblocking any for-range consumer.
	result := make(chan T)
	done := make(chan struct{})

	callback := func(key, value any) {
		// intermediate is never closed, so this select can never panic.
		select {
		case <-done:
		case intermediate <- value.(T):
		}
	}

	c := cache.NewTTLWithCallback(cooldown, evictionInterval, callback)

	q := &CooldownQueue[T]{
		seenEvents: c,
		innerChan:  intermediate,
		resultChan: result,
		done:       done,
	}

	// Relay goroutine: forwards events from intermediate to result and closes
	// result when the queue is stopped.
	go func() {
		defer close(result)
		for {
			select {
			case <-done:
				return
			case v := <-intermediate:
				select {
				case <-done:
					return
				case result <- v:
				}
			}
		}
	}()

	return q
}

func (q *CooldownQueue[T]) Closed() bool {
	return q.closed.Load()
}

// Enqueue enqueues an event in the Cooldown Queue
func (q *CooldownQueue[T]) Enqueue(e T, key string) {
	if q.closed.Load() {
		return
	}

	q.seenEvents.Set(key, e)
}

// Stop signals the queue to shut down. The result channel is closed by the
// relay goroutine once all in-flight sends have drained, unblocking any
// for-range consumer.
func (q *CooldownQueue[T]) Stop() {
	if q.closed.Swap(true) {
		return // already stopped
	}
	close(q.done)
}

// ResultChan returns a read-only channel for consuming events.
func (q *CooldownQueue[T]) ResultChan() <-chan T {
	return q.resultChan
}
