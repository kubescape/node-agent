package contextdetection

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
)

type EventSourceContext string

const (
	Kubernetes EventSourceContext = "kubernetes"
	Host       EventSourceContext = "host"
	Standalone EventSourceContext = "standalone"
)

type ContextInfo interface {
	Context() EventSourceContext
	WorkloadID() string
}

type ContextDetector interface {
	Detect(container *containercollection.Container) (ContextInfo, bool)
	Priority() int
}
