package containerwatcher

import (
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/utils"
)

// NewEnrichedEvent creates a new enriched event
func NewEnrichedEvent(eventType utils.EventType, event utils.K8sEvent, timestamp time.Time, containerID string, processTree apitypes.Process) *containerwatcher.EnrichedEvent {
	return &containerwatcher.EnrichedEvent{
		EventType:   eventType,
		Event:       event,
		Timestamp:   timestamp,
		ContainerID: containerID,
		ProcessTree: processTree,
	}
}
