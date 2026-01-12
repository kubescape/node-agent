package detectors

import (
	"os"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/contextdetection"
)

type HostContextInfo struct {
	HostName string
}

func (h *HostContextInfo) Context() contextdetection.EventSourceContext {
	return contextdetection.Host
}

// WorkloadID returns the hostname as the workload identifier for host contexts.
// Returns the system hostname if available, or "host" as a fallback.
// This identifier is unique and deterministic within host contexts.
func (h *HostContextInfo) WorkloadID() string {
	if h.HostName != "" {
		return h.HostName
	}
	return "host"
}

type HostDetector struct {
	name     string
	hostName string
}

func NewHostDetector() *HostDetector {
	hostName, _ := os.Hostname()
	return &HostDetector{
		name:     "HostDetector",
		hostName: hostName,
	}
}

func (hd *HostDetector) Detect(container *containercollection.Container) (contextdetection.ContextInfo, bool) {
	if container == nil {
		return nil, false
	}

	if container.K8s.PodName != "" || container.K8s.Namespace != "" {
		return nil, false
	}

	if container.Runtime.ContainerID != "" {
		hostInfo := &HostContextInfo{HostName: hd.hostName}
		return hostInfo, true
	}

	return nil, false
}

func (hd *HostDetector) Priority() int {
	return 1
}
