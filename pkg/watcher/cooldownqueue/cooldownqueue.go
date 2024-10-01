package cooldownqueue

import (
	"strings"
	"time"

	"istio.io/pkg/cache"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

const (
	defaultExpiration = 5 * time.Second
	evictionInterval  = 1 * time.Second
)

// CooldownQueue is a queue that lets clients put events into it with a cooldown
//
// When a client puts an event into a queue, it waits for a cooldown period before
// the event is forwarded to the consumer. If and event for the same key is put into the queue
// again before the cooldown period is over, the event is overridden and the cooldown period is reset.
type CooldownQueue struct {
	closed     bool
	seenEvents cache.ExpiringCache
	// inner channel for producing events
	innerChan chan watch.Event
	// public channel for reading events
	ResultChan <-chan watch.Event
}

// NewCooldownQueue returns a new Cooldown Queue
func NewCooldownQueue() *CooldownQueue {
	events := make(chan watch.Event)
	callback := func(key, value any) {
		events <- value.(watch.Event)
	}
	c := cache.NewTTLWithCallback(defaultExpiration, evictionInterval, callback)
	return &CooldownQueue{
		seenEvents: c,
		innerChan:  events,
		ResultChan: events,
	}
}

// makeEventKey creates a unique key for an event from a watcher
func makeEventKey(e watch.Event) string {
	gvk := e.Object.GetObjectKind().GroupVersionKind()
	meta := e.Object.(metav1.Object)
	return strings.Join([]string{gvk.Group, gvk.Version, gvk.Kind, meta.GetNamespace(), meta.GetName()}, "/")
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
	q.seenEvents.Set(eventKey, e)
}

func (q *CooldownQueue) Stop() {
	q.closed = true
	close(q.innerChan)
}
