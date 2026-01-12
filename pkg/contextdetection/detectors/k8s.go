package detectors

import (
	"fmt"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/contextdetection"
)

type K8sContextInfo struct {
	Namespace   string
	PodName     string
	Workload    string
	WorkloadUID string
}

func (k *K8sContextInfo) Context() contextdetection.EventSourceContext {
	return contextdetection.Kubernetes
}

// WorkloadID returns the Kubernetes workload identifier in the format "namespace/podname".
// This format is standardized and deterministic within Kubernetes contexts.
func (k *K8sContextInfo) WorkloadID() string {
	return fmt.Sprintf("%s/%s", k.Namespace, k.PodName)
}

type K8sDetector struct {
	name string
}

func NewK8sDetector() *K8sDetector {
	return &K8sDetector{name: "K8sDetector"}
}

func (kd *K8sDetector) Detect(container *containercollection.Container) (contextdetection.ContextInfo, bool) {
	if container == nil {
		return nil, false
	}

	if container.K8s.PodName == "" || container.K8s.Namespace == "" {
		return nil, false
	}

	k8sInfo := &K8sContextInfo{
		Namespace: container.K8s.Namespace,
		PodName:   container.K8s.PodName,
	}

	return k8sInfo, true
}

func (kd *K8sDetector) Priority() int {
	return 0
}
