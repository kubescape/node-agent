package contextdetection

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
)

type EventSourceContext string

const (
	Kubernetes EventSourceContext = "kubernetes"
	Host       EventSourceContext = "host"
	Standalone EventSourceContext = "standalone"
	Container  EventSourceContext = "container"
	ECS        EventSourceContext = "ecs"
)

type ContextInfo interface {
	Context() EventSourceContext
	WorkloadID() string
}

type ContextDetector interface {
	Detect(container *containercollection.Container) (ContextInfo, bool)
	Priority() int
}
