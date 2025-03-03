package objectcache

import (
	"time"

	"github.com/kubescape/node-agent/pkg/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "k8s.io/api/core/v1"
)

func UniqueName(namespace, name string) string {
	return namespace + "/" + name
}

func MetaUniqueName(obj metav1.Object) string {
	return UniqueName(obj.GetNamespace(), obj.GetName())
}

// list containerIDs from pod status
func ListContainersIDs(pod *corev1.Pod) []string {
	var containers []string

	for _, s := range pod.Status.ContainerStatuses {
		containers = append(containers, utils.TrimRuntimePrefix(s.ContainerID))
	}
	for _, s := range pod.Status.InitContainerStatuses {
		containers = append(containers, utils.TrimRuntimePrefix(s.ContainerID))
	}
	for _, s := range pod.Status.EphemeralContainerStatuses {
		containers = append(containers, utils.TrimRuntimePrefix(s.ContainerID))
	}
	return containers
}

// list terminated containers from pod status
func ListTerminatedContainers(pod *corev1.Pod) []string {
	var containers []string

	for _, s := range pod.Status.ContainerStatuses {
		if s.State.Terminated != nil {
			containers = append(containers, utils.TrimRuntimePrefix(s.ContainerID))
		}
	}
	for _, s := range pod.Status.InitContainerStatuses {
		if s.State.Terminated != nil {
			containers = append(containers, utils.TrimRuntimePrefix(s.ContainerID))
		}
	}
	for _, s := range pod.Status.EphemeralContainerStatuses {
		if s.State.Terminated != nil {
			containers = append(containers, utils.TrimRuntimePrefix(s.ContainerID))
		}
	}
	return containers
}

// GetTerminationExitCode returns the termination exit code of the container, otherwise -1
func GetTerminationExitCode(k8sObjectsCache K8sObjectCache, namespace, podName, containerName, containerID string) int32 {
	notFound := int32(-1)
	time.Sleep(3 * time.Second)
	podStatus := k8sObjectsCache.GetPodStatus(namespace, podName)
	if podStatus == nil {
		return notFound
	}

	// check only container status
	// in case the terminated container is an init or ephemeral container
	// return -1 to avoid setting the status later to completed
	for _, s := range podStatus.ContainerStatuses {
		if s.Name != containerName {
			continue
		}
		if s.State.Running != nil {
			return notFound
		}
		if s.LastTerminationState.Terminated != nil {
			// trim ID
			if containerID == utils.TrimRuntimePrefix(s.LastTerminationState.Terminated.ContainerID) {
				return s.LastTerminationState.Terminated.ExitCode
			}
		}
	}

	return notFound
}
