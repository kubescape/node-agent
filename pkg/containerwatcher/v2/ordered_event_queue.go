package containerwatcher

import (
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/processtree"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/oleiade/lane/v2"
)

type eventEntry struct {
	EventType   utils.EventType
	Event       utils.K8sEvent
	Timestamp   time.Time
	ContainerID string
	ProcessID   uint32
}

type OrderedEventQueue struct {
	maxBufferSize      int
	eventQueue         *lane.PriorityQueue[eventEntry, int64]
	fullQueueAlert     chan struct{}
	processTreeManager processtree.ProcessTreeManager
}

func NewOrderedEventQueue(collectionInterval time.Duration, maxBufferSize int, processTreeManager processtree.ProcessTreeManager) *OrderedEventQueue {
	return &OrderedEventQueue{
		maxBufferSize:      maxBufferSize,
		eventQueue:         lane.NewMinPriorityQueue[eventEntry, int64](),
		fullQueueAlert:     make(chan struct{}, 1),
		processTreeManager: processTreeManager,
	}
}

func (oeq *OrderedEventQueue) GetFullQueueAlertChannel() <-chan struct{} {
	return oeq.fullQueueAlert
}

func (oeq *OrderedEventQueue) AddEventDirect(eventType utils.EventType, event utils.K8sEvent, containerID string, processID uint32) {
	timestamp := time.Unix(0, int64(event.GetTimestamp()))

	eventEntry := eventEntry{
		EventType:   eventType,
		Event:       event,
		Timestamp:   timestamp,
		ContainerID: containerID,
		ProcessID:   processID,
	}

	priority := timestamp.UnixNano()
	oeq.eventQueue.Push(eventEntry, priority)

	if oeq.eventQueue.Size() >= uint(oeq.maxBufferSize) {
		logger.L().Warning("Ordered event queue - Event queue full, sending processing alert",
			helpers.Int("queueSize", int(oeq.eventQueue.Size())),
			helpers.Int("maxBufferSize", oeq.maxBufferSize))

		select {
		case oeq.fullQueueAlert <- struct{}{}:
		default:
		}
	}
}

func (oeq *OrderedEventQueue) PopEvent() (eventEntry, bool) {
	if oeq.eventQueue.Empty() {
		return eventEntry{}, false
	}

	event, _, ok := oeq.eventQueue.Pop()
	return event, ok
}

func (oeq *OrderedEventQueue) PeekEvent() (eventEntry, bool) {
	if oeq.eventQueue.Empty() {
		return eventEntry{}, false
	}

	event, _, ok := oeq.eventQueue.Head()
	return event, ok
}

// Size returns the number of events in the queue
func (oeq *OrderedEventQueue) Size() int {
	return int(oeq.eventQueue.Size())
}

// Empty returns whether the queue is empty
func (oeq *OrderedEventQueue) Empty() bool {
	return oeq.eventQueue.Empty()
}
