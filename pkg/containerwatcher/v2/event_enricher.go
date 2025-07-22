package containerwatcher

import (
	"fmt"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	ebpfevents "github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/processtree"
	"github.com/kubescape/node-agent/pkg/utils"
)

// EventEnricher handles event enrichment with metrics and logging
type EventEnricher struct {
	processTreeManager processtree.ProcessTreeManager
}

// NewEventEnricher creates a new event enricher
func NewEventEnricher(
	processTreeManager processtree.ProcessTreeManager,
) *EventEnricher {
	return &EventEnricher{
		processTreeManager: processTreeManager,
	}
}

func (ee *EventEnricher) EnrichEvents(entry eventEntry) *ebpfevents.EnrichedEvent {
	eventType := entry.EventType
	event := entry.Event

	if isProcessTreeEvent(eventType) {
		if err := ee.processTreeManager.ReportEvent(eventType, event); err != nil {
			logger.L().Error("Failed to report event to process tree", helpers.Error(err),
				helpers.String("eventType", string(eventType)),
				helpers.String("pid", fmt.Sprintf("%d", entry.ProcessID)))
		}
	}

	processTree, _ := ee.processTreeManager.GetContainerProcessTree(entry.ContainerID, entry.ProcessID)

	enrichedEvent := &ebpfevents.EnrichedEvent{
		Event:       event,
		EventType:   eventType,
		ProcessTree: processTree,
		ContainerID: entry.ContainerID,
		Timestamp:   entry.Timestamp,
		PID:         entry.ProcessID,
	}

	return enrichedEvent
}

// isProcessTreeEvent checks if an event type is related to process tree
func isProcessTreeEvent(eventType utils.EventType) bool {
	return eventType == utils.ExecveEventType ||
		eventType == utils.ExitEventType ||
		eventType == utils.ForkEventType ||
		eventType == utils.ProcfsEventType
}
