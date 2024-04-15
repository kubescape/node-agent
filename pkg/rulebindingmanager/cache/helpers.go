package cache

import (
	"fmt"
	typesv1 "node-agent/pkg/rulebindingmanager/types/v1"
	"node-agent/pkg/watcher"
	"strings"

	k8sruntime "k8s.io/apimachinery/pkg/runtime"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func uniqueNameToName(n string) (string, string) {
	if str := strings.Split(n, "/"); len(str) == 2 {
		return str[0], str[1]
	}
	return "", ""
}
func uniqueName(namespace, name string) string {
	return fmt.Sprintf("%s/%s", namespace, name)
}
func podUniqueName(pod *corev1.Pod) string {
	return uniqueName(pod.GetNamespace(), pod.GetName())
}
func rbUniqueName(rb *typesv1.RuntimeAlertRuleBinding) string {
	return uniqueName(rb.GetNamespace(), rb.GetName())
}

func unstructuredUniqueName(obj *unstructured.Unstructured) string {
	return uniqueName(obj.GetNamespace(), obj.GetName())
}

func unstructuredToRuleBinding(obj *unstructured.Unstructured) (*typesv1.RuntimeAlertRuleBinding, error) {
	rb := &typesv1.RuntimeAlertRuleBinding{}
	if err := k8sruntime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, rb); err != nil {
		return nil, err
	}
	return rb, nil
}
func unstructuredToPod(obj *unstructured.Unstructured) (*corev1.Pod, error) {
	pod := &corev1.Pod{}
	if err := k8sruntime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, pod); err != nil {
		return nil, err
	}
	return pod, nil

}
func resourcesToWatch(nodeName string) []watcher.WatchResource {
	w := []watcher.WatchResource{}

	// add pod
	p := watcher.NewWatchResource(schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "pods",
	},
		metav1.ListOptions{
			FieldSelector: "spec.nodeName=" + nodeName,
		},
	)
	w = append(w, p)

	// add rule binding
	rb := watcher.NewWatchResource(typesv1.RuleBindingAlertGvr, metav1.ListOptions{})
	w = append(w, rb)

	return w
}
