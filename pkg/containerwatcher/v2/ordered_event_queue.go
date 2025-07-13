package containerwatcher

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/processtree"
	"github.com/kubescape/node-agent/pkg/utils"
)

// eventEntry represents an event in the queue with its type and timestamp
type eventEntry struct {
	EventType   utils.EventType
	Event       utils.K8sEvent
	Timestamp   time.Time
	ContainerID string
	ProcessID   uint32
}

// OrderedEventQueue manages a queue of events that are collected and sorted by timestamp
type OrderedEventQueue struct {
	// Configuration
	collectionInterval time.Duration
	maxBufferSize      int

	// Event collection
	eventBuffer []eventEntry
	bufferMutex sync.Mutex

	// Output channel - only sorted events
	outputChan chan []eventEntry

	// Process tree manager for enriching events
	processTreeManager processtree.ProcessTreeManager

	// Lifecycle
	ctx     context.Context
	cancel  context.CancelFunc
	started bool
	stopped bool
}

// NewOrderedEventQueue creates a new ordered event queue
func NewOrderedEventQueue(collectionInterval time.Duration, maxBufferSize int, processTreeManager processtree.ProcessTreeManager) *OrderedEventQueue {
	return &OrderedEventQueue{
		collectionInterval: collectionInterval,
		maxBufferSize:      maxBufferSize,
		eventBuffer:        make([]eventEntry, 0, maxBufferSize),
		processTreeManager: processTreeManager,
		outputChan:         make(chan []eventEntry, 10),
	}
}

// Start begins the event collection and processing
func (oeq *OrderedEventQueue) Start(ctx context.Context) error {
	oeq.bufferMutex.Lock()
	defer oeq.bufferMutex.Unlock()

	if oeq.started {
		return fmt.Errorf("ordered event queue already started")
	}

	if oeq.stopped {
		return fmt.Errorf("ordered event queue has been stopped and cannot be restarted")
	}

	oeq.ctx, oeq.cancel = context.WithCancel(ctx)
	oeq.started = true

	// Start the collection timer
	go oeq.collectionLoop()

	logger.L().Info("Ordered event queue started",
		helpers.String("collectionInterval", oeq.collectionInterval.String()),
		helpers.Int("maxBufferSize", oeq.maxBufferSize))

	return nil
}

// Stop gracefully stops the ordered event queue
func (oeq *OrderedEventQueue) Stop() {
	oeq.bufferMutex.Lock()
	defer oeq.bufferMutex.Unlock()

	if !oeq.started || oeq.stopped {
		return
	}

	oeq.stopped = true

	if oeq.cancel != nil {
		oeq.cancel()
	}

	// Process any remaining events
	oeq.processBufferLocked()

	// Close output channel
	close(oeq.outputChan)

	logger.L().Info("Ordered event queue stopped")
}

// GetOutputChannel returns the output channel for sorted events
func (oeq *OrderedEventQueue) GetOutputChannel() <-chan []eventEntry {
	return oeq.outputChan
}

// AddEventDirect adds an event directly to the buffer using the event's timestamp if available
func (oeq *OrderedEventQueue) AddEventDirect(eventType utils.EventType, event utils.K8sEvent, containerID string, processID uint32) {
	var timestamp time.Time
	if tsGetter, ok := event.(interface{ GetTimestamp() int64 }); ok {
		timestamp = time.Unix(0, tsGetter.GetTimestamp())
	} else {
		timestamp = time.Now()
	}
	oeq.addEvent(eventType, event, timestamp, containerID, processID)
}

// addEvent adds an event to the buffer
func (oeq *OrderedEventQueue) addEvent(eventType utils.EventType, event utils.K8sEvent, timestamp time.Time, containerID string, processID uint32) {
	oeq.bufferMutex.Lock()
	defer oeq.bufferMutex.Unlock()

	if !oeq.started || oeq.stopped {
		logger.L().Warning("Ordered event queue not started or stopped, dropping event",
			helpers.String("eventType", string(eventType)))
		return
	}

	// Check if buffer is full - if so, trigger processing immediately
	if len(oeq.eventBuffer) >= oeq.maxBufferSize {
		logger.L().Warning("Event buffer full, triggering immediate processing",
			helpers.Int("bufferSize", len(oeq.eventBuffer)),
			helpers.Int("maxBufferSize", oeq.maxBufferSize))
		oeq.processBufferLocked()
	}

	eventEntry := eventEntry{
		EventType:   eventType,
		Event:       event,
		Timestamp:   timestamp,
		ContainerID: containerID,
		ProcessID:   processID,
	}

	oeq.eventBuffer = append(oeq.eventBuffer, eventEntry)
}

// collectionLoop runs the periodic collection and processing of events
func (oeq *OrderedEventQueue) collectionLoop() {
	ticker := time.NewTicker(oeq.collectionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-oeq.ctx.Done():
			return
		case <-ticker.C:
			oeq.processBuffer()
		}
	}
}

// processBuffer processes the current buffer of events
func (oeq *OrderedEventQueue) processBuffer() {
	oeq.bufferMutex.Lock()
	defer oeq.bufferMutex.Unlock()
	oeq.processBufferLocked()
}

// processBufferLocked processes the current buffer of events (assumes mutex is already held)
func (oeq *OrderedEventQueue) processBufferLocked() {
	if len(oeq.eventBuffer) == 0 {
		return
	}

	// Sort events by timestamp
	sort.Slice(oeq.eventBuffer, func(i, j int) bool {
		return oeq.eventBuffer[i].Timestamp.Before(oeq.eventBuffer[j].Timestamp)
	})

	// Create a copy of the buffer for output
	eventsToOutput := make([]eventEntry, len(oeq.eventBuffer))
	copy(eventsToOutput, oeq.eventBuffer)

	// Clear the buffer
	oeq.eventBuffer = oeq.eventBuffer[:0]

	// Send sorted events to output channel
	select {
	case oeq.outputChan <- eventsToOutput:
		// logger.L().Debug("Sent sorted events to output", helpers.Int("eventCount", len(eventsToOutput)))
	default:
		// logger.L().Warning("Output channel full, dropping events", helpers.Int("eventCount", len(eventsToOutput)))
	}
}
