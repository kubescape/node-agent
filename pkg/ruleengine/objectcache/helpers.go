package objectcache

import (
	"encoding/json"

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
