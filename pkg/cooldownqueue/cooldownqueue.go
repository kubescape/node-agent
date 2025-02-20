package cooldownqueue

import (
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
// the event is forwarded to the consumer. If and event for the same key is put into the queue
// again before the cooldown period is over, the event is overridden and the cooldown period is reset.
type CooldownQueue[T any] struct {
	closed     bool
	seenEvents cache.ExpiringCache
	innerChan  chan T   // Private channel
	resultChan <-chan T // Read-only public channel
}

// NewCooldownQueue returns a new Cooldown Queue
func NewCooldownQueue[T any](cooldown time.Duration, evictionInterval time.Duration) *CooldownQueue[T] {
	events := make(chan T)
	callback := func(key, value any) {
		events <- value.(T)
	}
	c := cache.NewTTLWithCallback(cooldown, evictionInterval, callback)
	return &CooldownQueue[T]{
		seenEvents: c,
		innerChan:  events,
		resultChan: events,
	}
}

func (q *CooldownQueue[T]) Closed() bool {
	return q.closed
}

// Enqueue enqueues an event in the Cooldown Queue
func (q *CooldownQueue[T]) Enqueue(e T, key string) {
	if q.closed {
		return
	}

	q.seenEvents.Set(key, e)
}

func (q *CooldownQueue[T]) Stop() {
	q.closed = true
	close(q.innerChan)
}

// ResultChan returns a read-only channel for consuming events.
func (q *CooldownQueue[T]) ResultChan() <-chan T {
	return q.resultChan
}
