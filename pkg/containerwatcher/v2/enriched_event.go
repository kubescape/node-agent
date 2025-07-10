package containerwatcher

import (
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/utils"
)

// EnrichedEvent represents an event with its process tree and metadata
type EnrichedEvent struct {
	EventType   utils.EventType
	Event       utils.K8sEvent
	Timestamp   time.Time
	ContainerID string
	ProcessTree apitypes.Process
}

// NewEnrichedEvent creates a new enriched event
func NewEnrichedEvent(eventType utils.EventType, event utils.K8sEvent, timestamp time.Time, containerID string, processTree apitypes.Process) *EnrichedEvent {
	return &EnrichedEvent{
		EventType:   eventType,
		Event:       event,
		Timestamp:   timestamp,
		ContainerID: containerID,
		ProcessTree: processTree,
	}
}
