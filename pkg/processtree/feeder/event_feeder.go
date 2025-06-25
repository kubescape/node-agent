package feeder

import (
	"context"
	"sync"
	"time"

	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/utils"
)

// EventFeeder implements ProcessEventFeeder by receiving events from container watcher
type EventFeeder struct {
	subscribers []chan<- ProcessEvent
	mutex       sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
	started     bool
}

// NewEventFeeder creates a new event feeder
func NewEventFeeder() *EventFeeder {
	return &EventFeeder{}
}

// Start begins the event feeder
func (ef *EventFeeder) Start(ctx context.Context) error {
	ef.mutex.Lock()
	defer ef.mutex.Unlock()

	if ef.started {
		return nil // Already started
	}

	ef.ctx, ef.cancel = context.WithCancel(ctx)
	ef.started = true

	return nil
}

// Stop stops the event feeder
func (ef *EventFeeder) Stop() error {
	ef.mutex.Lock()
	defer ef.mutex.Unlock()

	if ef.cancel != nil {
		ef.cancel()
	}

	return nil
}

// Subscribe adds a channel to receive process events
func (ef *EventFeeder) Subscribe(ch chan<- ProcessEvent) {
	ef.mutex.Lock()
	defer ef.mutex.Unlock()

	ef.subscribers = append(ef.subscribers, ch)
}

// ReportEvent handles events from the container watcher and converts them to ProcessEvent
func (ef *EventFeeder) ReportEvent(eventType utils.EventType, event utils.K8sEvent) {
	ef.mutex.RLock()
	defer ef.mutex.RUnlock()

	if !ef.started {
		return
	}

	var processEvent ProcessEvent

	switch eventType {
	case utils.ExecveEventType:
		processEvent = ef.convertExecEvent(event.(*events.ExecEvent))
	default:
		// Unknown event type, ignore
		return
	}

	ef.broadcastEvent(processEvent)
}

// convertExecEvent converts an ExecEvent to ProcessEvent
func (ef *EventFeeder) convertExecEvent(execEvent *events.ExecEvent) ProcessEvent {
	event := ProcessEvent{
		Type:        ExecEvent,
		Timestamp:   time.Now(),
		PID:         execEvent.Pid,
		PPID:        execEvent.Ppid,
		Comm:        execEvent.Comm,
		Path:        execEvent.ExePath,
		StartTimeNs: uint64(time.Now().UnixNano()), // Use current time as start time for now
	}

	// Convert command line arguments to string
	if len(execEvent.Args) > 0 {
		// Join all arguments with spaces
		cmdline := ""
		for i, arg := range execEvent.Args {
			if i > 0 {
				cmdline += " "
			}
			cmdline += arg
		}
		event.Cmdline = cmdline
	}

	// Set UID and GID if available
	if execEvent.Uid != 0 {
		uid := execEvent.Uid
		event.Uid = &uid
	}
	if execEvent.Gid != 0 {
		gid := execEvent.Gid
		event.Gid = &gid
	}

	// Set container context if available
	if execEvent.Runtime.ContainerID != "" {
		event.ContainerID = execEvent.Runtime.ContainerID
	}

	return event
}

// broadcastEvent sends an event to all subscribers
func (ef *EventFeeder) broadcastEvent(event ProcessEvent) {
	for _, ch := range ef.subscribers {
		select {
		case ch <- event:
		default:
			// Channel is full, skip this subscriber
			// In a real implementation, you might want to log this
		}
	}
}
