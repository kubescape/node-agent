package containerwatcher

import (
	"fmt"
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/processtree"
	"github.com/kubescape/node-agent/pkg/processtree/feeder"
	"github.com/kubescape/node-agent/pkg/utils"
)

// EventEnricher handles event enrichment with metrics and logging
type EventEnricher struct {
	processTreeManager processtree.ProcessTreeManager
	processTreeFeeder  *feeder.EventFeeder

	// Metrics
	totalEventsProcessed int64
	totalProcessingTime  time.Duration
	metricsMutex         sync.RWMutex
}

// NewEventEnricher creates a new event enricher
func NewEventEnricher(
	processTreeManager processtree.ProcessTreeManager,
	processTreeFeeder *feeder.EventFeeder,
) *EventEnricher {
	return &EventEnricher{
		processTreeManager: processTreeManager,
		processTreeFeeder:  processTreeFeeder,
	}
}

func (ee *EventEnricher) EnrichEvents(events []eventEntry) []*containerwatcher.EnrichedEvent {
	startTime := time.Now()

	enrichedEvents := make([]*containerwatcher.EnrichedEvent, 0, len(events))

	for _, entry := range events {
		event := entry.Event
		eventType := entry.EventType

		if isProcessTreeEvent(eventType) {
			ee.processTreeFeeder.ReportEvent(eventType, event)
		}

		if eventType == utils.ProcfsEventType {
			continue
		}

		processTree, err := ee.processTreeManager.GetContainerProcessTree(entry.ContainerID, entry.ProcessID)
		if err != nil {
			if eventType == utils.ExecveEventType {
				logger.L().Error("PROC - Failed to get container process tree", helpers.Error(err),
					helpers.String("pid", fmt.Sprintf("%d", entry.ProcessID)),
					helpers.String("containerID", entry.ContainerID))
			}
			continue
		}

		enrichedEvents = append(enrichedEvents, &containerwatcher.EnrichedEvent{
			Event:       event,
			EventType:   eventType,
			ProcessTree: processTree,
			ContainerID: entry.ContainerID,
			Timestamp:   entry.Timestamp,
		})
	}

	processingTime := time.Since(startTime)

	logger.L().Info("PROC - Enriched events", helpers.Int("enrichedEvents", len(enrichedEvents)))

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
