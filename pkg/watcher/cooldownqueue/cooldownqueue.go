package cooldownqueue

import (
	"strings"
	"time"

	"istio.io/pkg/cache"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
)

var (
	DefaultExpiration = 5 * time.Second
	EvictionInterval  = 1 * time.Second
)

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
	c := cache.NewTTLWithCallback(DefaultExpiration, EvictionInterval, callback)
	return &CooldownQueue{
		seenEvents: c,
		innerChan:  events,
		ResultChan: events,
	}
}

// makeEventKey creates a unique key for an event from a watcher
func makeEventKey(e watch.Event) string {
	object := e.Object.(runtime.Object)
	gvk := object.GetObjectKind().GroupVersionKind()
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
