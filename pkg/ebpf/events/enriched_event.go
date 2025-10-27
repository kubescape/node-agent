package events

import (
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/utils"
)

// NewEnrichedEvent creates a new enriched event
func NewEnrichedEvent(event utils.K8sEvent, timestamp time.Time, containerID string, processTree apitypes.Process) *EnrichedEvent {
	return &EnrichedEvent{
		Event:       event,
		Timestamp:   timestamp,
		ContainerID: containerID,
		ProcessTree: processTree,
	}
}

type EnrichedEvent struct {
	Event       utils.K8sEvent
	Timestamp   time.Time
	ContainerID string
	ProcessTree apitypes.Process
	PID         uint32
	PPID        uint32
}
