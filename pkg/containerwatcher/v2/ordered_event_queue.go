package containerwatcher

import (
	"fmt"
	"reflect"
	"time"

	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
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
	maxBufferSize int

	eventQueue *lane.PriorityQueue[eventEntry, int64]

	fullQueueAlert chan struct{}

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
	var timestamp time.Time

	// Try to get timestamp using reflection to access the embedded Timestamp field
	eventValue := reflect.ValueOf(event)
	if eventValue.Kind() == reflect.Ptr {
		eventValue = eventValue.Elem()
	}

	timestampField := eventValue.FieldByName("Timestamp")
	if timestampField.IsValid() && timestampField.CanInterface() {
		if ts, ok := timestampField.Interface().(igtypes.Time); ok {
			timestamp = time.Unix(0, int64(ts))
		} else if ts, ok := timestampField.Interface().(int64); ok {
			timestamp = time.Unix(0, ts)
		} else if ts, ok := timestampField.Interface().(time.Time); ok {
			timestamp = ts
		} else {
			logger.L().Warning("AFEK - Ordered event queue - Timestamp field has unexpected type",
				helpers.String("eventType", string(eventType)),
				helpers.String("containerID", containerID),
				helpers.String("timestampType", fmt.Sprintf("%T", timestampField.Interface())))
			timestamp = time.Now()
		}
	} else {
		// Fallback: use current time
		logger.L().Warning("AFEK - Ordered event queue - Event has no timestamp, using current time",
			helpers.String("eventType", string(eventType)),
			helpers.String("containerID", containerID))
		timestamp = time.Now()
	}

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
		logger.L().Warning("AFEK - Ordered event queue - Event queue full, sending processing alert",
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
