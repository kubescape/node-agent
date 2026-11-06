package containerwatcher

import (
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/utils"
)

type EventEntry struct {
	EventType   utils.EventType
	Event       utils.K8sEvent
	Timestamp   time.Time
	ContainerID string
	ProcessID   uint32
}

// DroppedEvents is the number of events of one type dropped for one container
// because the queue was full. ContainerID may be empty for events that cannot
// be attributed to a container.
type DroppedEvents struct {
	EventType   utils.EventType
	ContainerID string
	Count       int64
}

type droppedKey struct {
	eventType   utils.EventType
	containerID string
}

type OrderedEventQueue struct {
	maxBufferSize  int
	eventQueue     []EventEntry
	mutex          sync.Mutex
	fullQueueAlert chan struct{}
	// dropped is guarded by mutex. It is bounded by the number of distinct
	// (event type, container) pairs seen between two DrainDropped calls.
	dropped map[droppedKey]int64
}

func NewOrderedEventQueue(collectionInterval time.Duration, maxBufferSize int) *OrderedEventQueue {
	return &OrderedEventQueue{
		maxBufferSize:  maxBufferSize,
		eventQueue:     make([]EventEntry, 0, 1024),
		fullQueueAlert: make(chan struct{}, 1),
	}
}

func (oeq *OrderedEventQueue) GetFullQueueAlertChannel() <-chan struct{} {
	return oeq.fullQueueAlert
}

func (oeq *OrderedEventQueue) AddEventDirect(eventType utils.EventType, event utils.K8sEvent, containerID string, processID uint32) {
	oeq.mutex.Lock()
	if len(oeq.eventQueue) >= oeq.maxBufferSize {
		queueSize := len(oeq.eventQueue)
		// Only record the drop here; metrics and profile updates are applied
		// from the processing loop via DrainDropped so this callback never
		// waits on per-container locks.
		if oeq.dropped == nil {
			oeq.dropped = make(map[droppedKey]int64)
		}
		oeq.dropped[droppedKey{eventType: eventType, containerID: containerID}]++
		oeq.mutex.Unlock()

		logger.L().Warning("Ordered event queue - Event queue full, dropping event to prevent OOM",
			helpers.String("eventType", string(eventType)),
			helpers.String("containerID", containerID),
			helpers.Int("queueSize", queueSize),
			helpers.Int("maxBufferSize", oeq.maxBufferSize))

		select {
		case oeq.fullQueueAlert <- struct{}{}:
		default:
		}

		event.Release()
		return
	}

	timestamp := time.Unix(0, int64(event.GetTimestamp()))

	eventEntry := EventEntry{
		EventType:   eventType,
		Event:       event,
		Timestamp:   timestamp,
		ContainerID: containerID,
		ProcessID:   processID,
	}

	oeq.pushHeap(eventEntry)
	oeq.mutex.Unlock()
}

// DrainDropped appends the drops recorded since the previous call to dst[:0]
// and resets the counters.
func (oeq *OrderedEventQueue) DrainDropped(dst []DroppedEvents) []DroppedEvents {
	oeq.mutex.Lock()
	defer oeq.mutex.Unlock()

	dst = dst[:0]
	for key, count := range oeq.dropped {
		dst = append(dst, DroppedEvents{EventType: key.eventType, ContainerID: key.containerID, Count: count})
		delete(oeq.dropped, key)
	}
	return dst
}

func (oeq *OrderedEventQueue) PopEvent() (EventEntry, bool) {
	oeq.mutex.Lock()
	defer oeq.mutex.Unlock()

	if len(oeq.eventQueue) == 0 {
		return EventEntry{}, false
	}

	return oeq.popHeap(), true
}

func (oeq *OrderedEventQueue) PopBatch(maxCount int, dst []EventEntry) []EventEntry {
	oeq.mutex.Lock()
	defer oeq.mutex.Unlock()

	dst = dst[:0]
	for len(oeq.eventQueue) > 0 && len(dst) < maxCount {
		dst = append(dst, oeq.popHeap())
	}
	return dst
}

func (oeq *OrderedEventQueue) PeekEvent() (EventEntry, bool) {
	oeq.mutex.Lock()
	defer oeq.mutex.Unlock()

	if len(oeq.eventQueue) == 0 {
		return EventEntry{}, false
	}

	return oeq.eventQueue[0], true
}

// Size returns the number of events in the queue
func (oeq *OrderedEventQueue) Size() int {
	oeq.mutex.Lock()
	defer oeq.mutex.Unlock()
	return len(oeq.eventQueue)
}

// Empty returns whether the queue is empty
func (oeq *OrderedEventQueue) Empty() bool {
	oeq.mutex.Lock()
	defer oeq.mutex.Unlock()
	return len(oeq.eventQueue) == 0
}

func (oeq *OrderedEventQueue) pushHeap(entry EventEntry) {
	oeq.eventQueue = append(oeq.eventQueue, entry)
	oeq.up(len(oeq.eventQueue) - 1)
}

func (oeq *OrderedEventQueue) popHeap() EventEntry {
	n := len(oeq.eventQueue) - 1
	oeq.eventQueue[0], oeq.eventQueue[n] = oeq.eventQueue[n], oeq.eventQueue[0]
	oeq.down(0, n)
	x := oeq.eventQueue[n]
	oeq.eventQueue[n] = EventEntry{}
	oeq.eventQueue = oeq.eventQueue[:n]
	return x
}

func (oeq *OrderedEventQueue) up(j int) {
	for {
		i := (j - 1) / 2 // parent
		if i == j || !oeq.eventQueue[j].Timestamp.Before(oeq.eventQueue[i].Timestamp) {
			break
		}
		oeq.eventQueue[i], oeq.eventQueue[j] = oeq.eventQueue[j], oeq.eventQueue[i]
		j = i
	}
}

func (oeq *OrderedEventQueue) down(i0, n int) {
	i := i0
	for {
		j1 := 2*i + 1
		if j1 >= n || j1 < 0 {
			break
		}
		j := j1
		if j2 := j1 + 1; j2 < n && oeq.eventQueue[j2].Timestamp.Before(oeq.eventQueue[j1].Timestamp) {
			j = j2
		}
		if !oeq.eventQueue[j].Timestamp.Before(oeq.eventQueue[i].Timestamp) {
			break
		}
		oeq.eventQueue[i], oeq.eventQueue[j] = oeq.eventQueue[j], oeq.eventQueue[i]
		i = j
	}
}
