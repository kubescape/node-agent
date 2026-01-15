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

	if container.ContainerPid() == 1 {
		hostInfo := &HostContextInfo{HostName: hd.hostName}
		return hostInfo, true
	}

	return nil, false
}

func (hd *HostDetector) Priority() int {
	return 1
}
