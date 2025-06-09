package utils

import (
	"slices"
	"strings"

	v1 "k8s.io/api/core/v1"
)

type PatchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

func CreateK8sContainerID(namespaceName string, podName string, containerId string) string {
	return strings.Join([]string{namespaceName, podName, containerId}, "/")
}

func CreateK8sPodID(namespaceName string, podName string) string {
	return strings.Join([]string{namespaceName, podName}, "/")
}

// EscapeJSONPointerElement escapes a JSON pointer element
// See https://www.rfc-editor.org/rfc/rfc6901#section-3
func EscapeJSONPointerElement(s string) string {
	s = strings.ReplaceAll(s, "~", "~0")
	s = strings.ReplaceAll(s, "/", "~1")
	return s
}

// TrimRuntimePrefix removes the runtime prefix from a container ID.
func TrimRuntimePrefix(id string) string {
	parts := strings.SplitN(id, "//", 2)
	if len(parts) != 2 {
		return ""
	}

	return parts[1]
}

func GetContainerStatuses(podStatus v1.PodStatus) []v1.ContainerStatus {
	return slices.Concat(podStatus.ContainerStatuses, podStatus.InitContainerStatuses, podStatus.EphemeralContainerStatuses)
}

func MapContainerStatuses(statuses []v1.ContainerStatus) map[string]v1.ContainerStatus {
	statusesMap := make(map[string]v1.ContainerStatus)
	for _, s := range statuses {
		statusesMap[s.Name] = s
	}
	return statusesMap
}
