package containerwatcher

import (
	"fmt"
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/processtree"
	"github.com/kubescape/node-agent/pkg/utils"
)

// EventEnricher handles event enrichment with metrics and logging
type EventEnricher struct {
	processTreeManager processtree.ProcessTreeManager

	// Metrics
	totalEventsProcessed int64
	totalProcessingTime  time.Duration
	metricsMutex         sync.RWMutex
}

// NewEventEnricher creates a new event enricher
func NewEventEnricher(
	processTreeManager processtree.ProcessTreeManager,
) *EventEnricher {
	return &EventEnricher{
		processTreeManager: processTreeManager,
	}
}

func (ee *EventEnricher) EnrichEvents(events []eventEntry) []*containerwatcher.EnrichedEvent {
	startTime := time.Now()

	enrichedEvents := make([]*containerwatcher.EnrichedEvent, 0, len(events))

	for _, entry := range events {
		event := entry.Event
		eventType := entry.EventType

		if isProcessTreeEvent(eventType) {
			// Use the blocking ReportEvent method to ensure synchronous processing
			if err := ee.processTreeManager.ReportEvent(eventType, event); err != nil {
				logger.L().Error("PROC - Failed to report event to process tree", helpers.Error(err),
					helpers.String("eventType", string(eventType)),
					helpers.String("pid", fmt.Sprintf("%d", entry.ProcessID)))
			}
		}

		if eventType == utils.ProcfsEventType || eventType == utils.ForkEventType {
			continue
		}

		processTree, _ := ee.processTreeManager.GetBranch(entry.ProcessID, entry.ContainerID)

		enrichedEvents = append(enrichedEvents, &containerwatcher.EnrichedEvent{
			Event:       event,
			EventType:   eventType,
			ProcessTree: processTree,
			ContainerID: entry.ContainerID,
			Timestamp:   entry.Timestamp,
			PID:         entry.ProcessID,
		})
	}

	processingTime := time.Since(startTime)

	ee.updateMetrics(int64(len(events)), processingTime)

	return enrichedEvents
}

// updateMetrics updates the internal metrics counters
func (ee *EventEnricher) updateMetrics(eventCount int64, processingTime time.Duration) {
	ee.metricsMutex.Lock()
	defer ee.metricsMutex.Unlock()

	ee.totalEventsProcessed += eventCount
	ee.totalProcessingTime += processingTime
}

// isProcessTreeEvent checks if an event type is related to process tree
func isProcessTreeEvent(eventType utils.EventType) bool {
	return eventType == utils.ExecveEventType ||
		eventType == utils.ExitEventType ||
		eventType == utils.ForkEventType ||
		eventType == utils.ProcfsEventType
}
