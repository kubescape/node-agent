package objectcache

import (
	"encoding/json"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func UniqueName(namespace, name string) string {
	return namespace + "/" + name
}
func PodUniqueName(pod *corev1.Pod) string {
	return UniqueName(pod.GetNamespace(), pod.GetName())
}

func UnstructuredUniqueName(obj *unstructured.Unstructured) string {
	return UniqueName(obj.GetNamespace(), obj.GetName())
}

func UnstructuredToPod(obj *unstructured.Unstructured) (*corev1.Pod, error) {
	bytes, err := obj.MarshalJSON()
	if err != nil {
		return nil, err
	}

	var pod *corev1.Pod
	err = json.Unmarshal(bytes, &pod)
	if err != nil {
		return nil, err
	}
	return pod, nil
}

// list containerIDs from pod status
func ListContainersIDs(pod *corev1.Pod) []string {
	var containers []string

	for i := range pod.Status.ContainerStatuses {
		containers = append(containers, trimRuntimePrefix(pod.Status.ContainerStatuses[i].ContainerID))
	}
	for i := range pod.Status.InitContainerStatuses {
		containers = append(containers, trimRuntimePrefix(pod.Status.InitContainerStatuses[i].ContainerID))
	}
	for i := range pod.Status.EphemeralContainerStatuses {
		containers = append(containers, trimRuntimePrefix(pod.Status.EphemeralContainerStatuses[i].ContainerID))
	}
	return containers
}

// list terminated containers from pod status
func ListTerminatedContainers(pod *corev1.Pod) []string {
	var containers []string

	for i := range pod.Status.ContainerStatuses {
		if pod.Status.ContainerStatuses[i].State.Terminated != nil {
			containers = append(containers, trimRuntimePrefix(pod.Status.ContainerStatuses[i].ContainerID))
		}
	}
	for i := range pod.Status.InitContainerStatuses {
		if pod.Status.InitContainerStatuses[i].State.Terminated != nil {
			containers = append(containers, trimRuntimePrefix(pod.Status.InitContainerStatuses[i].ContainerID))
		}
	}
	for i := range pod.Status.EphemeralContainerStatuses {
		if pod.Status.EphemeralContainerStatuses[i].State.Terminated != nil {
			containers = append(containers, trimRuntimePrefix(pod.Status.EphemeralContainerStatuses[i].ContainerID))
		}
	}
	return containers
}

// trimRuntimePrefix removes the runtime prefix from a container ID.
func trimRuntimePrefix(id string) string {
	parts := strings.SplitN(id, "//", 2)
	if len(parts) != 2 {
		return ""
	}

	return parts[1]
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
	for i := range podStatus.ContainerStatuses {
		if podStatus.ContainerStatuses[i].Name != containerName {
			continue
		}
		if podStatus.ContainerStatuses[i].State.Running != nil {
			return notFound
		}
		if podStatus.ContainerStatuses[i].LastTerminationState.Terminated != nil {
			// trim ID
			if containerID == trimRuntimePrefix(podStatus.ContainerStatuses[i].LastTerminationState.Terminated.ContainerID) {
				return podStatus.ContainerStatuses[i].LastTerminationState.Terminated.ExitCode
			}
		}
	}

	return notFound
}
