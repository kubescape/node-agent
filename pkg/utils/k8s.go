package utils

import "strings"

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
