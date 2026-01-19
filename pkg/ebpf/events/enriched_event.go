package events

import (
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/contextdetection"
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
	Event              utils.K8sEvent
	Timestamp          time.Time
	ContainerID        string
	ProcessTree        apitypes.Process
	PID                uint32
	PPID               uint32
	// SourceContext holds the context information for this event (K8s, Host, or Standalone).
	// This is populated during event enrichment if the feature is enabled.
	// May be nil for legacy K8s-only events or when feature is disabled.
	SourceContext      contextdetection.ContextInfo
	// MountNamespaceID is the mount namespace ID from the container.
	// This uniquely identifies the container/host and is used for context lookup.
	// May be 0 if unavailable.
	MountNamespaceID   uint64
}
