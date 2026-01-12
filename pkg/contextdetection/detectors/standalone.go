package detectors

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/contextdetection"
)

type StandaloneContextInfo struct {
	ContainerID   string
	ContainerName string
}

func (s *StandaloneContextInfo) Context() contextdetection.EventSourceContext {
	return contextdetection.Standalone
}

// WorkloadID returns a unique identifier for standalone containers.
// Format priority:
// 1. "name:containerID" if both name and ID are available
// 2. containerName if ID is empty
// 3. containerID if name is empty
// This identifier is deterministic and unique within standalone contexts.
func (s *StandaloneContextInfo) WorkloadID() string {
	if s.ContainerID == "" {
		return s.ContainerName
	}
	if s.ContainerName != "" {
		return s.ContainerName + ":" + s.ContainerID
	}
	return s.ContainerID
}

type StandaloneDetector struct {
	name string
}

func NewStandaloneDetector() *StandaloneDetector {
	return &StandaloneDetector{name: "StandaloneDetector"}
}

func (sd *StandaloneDetector) Detect(container *containercollection.Container) (contextdetection.ContextInfo, bool) {
	if container == nil {
		return nil, false
	}

	standaloneInfo := &StandaloneContextInfo{
		ContainerID:   container.Runtime.ContainerID,
		ContainerName: container.Runtime.ContainerName,
	}

	return standaloneInfo, true
}

func (sd *StandaloneDetector) Priority() int {
	return 2
}
