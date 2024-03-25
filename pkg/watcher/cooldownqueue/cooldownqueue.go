package cooldownqueue

import (
	"time"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/watch"
)

var (
	// Default size for the cooldown queue
	DefaultQueueSize = 512
	// Default TTL for events put in the queue
	DefaultTTL = 1 * time.Second
)

// CooldownQueue is a queue that lets clients put events into it with a cooldown
//
// When a client puts an event into a queue, it forwards the event to its
// output channel and starts a cooldown for this event. If a client attempts to
// put the same event into the queue while the cooldown is running, the queue
// will silently drop the event. When the cooldown resets and a client puts the
// same event into the queue, it will be forwarded to the output channel
type CooldownQueue struct {
	seenEvents *lru.LRU[string, bool]
	innerChan  chan watch.Event
	ResultChan <-chan watch.Event
	closed     bool
}

// NewCooldownQueue returns a new Cooldown Queue
func NewCooldownQueue() *CooldownQueue {
	cache := lru.NewLRU[string, bool](DefaultQueueSize, nil, DefaultTTL)
	events := make(chan watch.Event)
	return &CooldownQueue{
		seenEvents: cache,
		innerChan:  events,
		ResultChan: events,
	}
}

// makeEventKey creates a unique key for an event from a watcher
func makeEventKey(e watch.Event) string {
	object, ok := e.Object.(*v1.Pod)
	if !ok {
		return ""
	}
	eventKey := string(e.Type) + "-" + string(object.GetUID())
	return eventKey
}

func (q *CooldownQueue) Closed() bool {
	return q.closed
}

// Enqueue enqueues an event in the Cooldown Queue
func (q *CooldownQueue) Enqueue(e watch.Event) {
	if q.closed {
		return
	}
	eventKey := makeEventKey(e)
	_, exists := q.seenEvents.Get(eventKey)
	if exists {
		return
	}
	go func() {
		q.innerChan <- e
	}()
	q.seenEvents.Add(eventKey, true)
}

func (q *CooldownQueue) Stop() {
	q.closed = true
	close(q.innerChan)
}
