package utils

import "strings"

func CreateK8sContainerID(namespaceName string, podName string, containerId string) string {
	return strings.Join([]string{namespaceName, podName, containerId}, "/")
}

func CreateK8sPodID(namespaceName string, podName string) string {
	return strings.Join([]string{namespaceName, podName}, "/")
}
