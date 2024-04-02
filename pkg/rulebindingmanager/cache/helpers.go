package cache

import (
	"encoding/json"
	"fmt"
	"node-agent/pkg/rulebindingmanager/types/v1"
	typesv1 "node-agent/pkg/rulebindingmanager/types/v1"
	"node-agent/pkg/watcher"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

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
	return fmt.Sprintf("%s/%s", obj.GetNamespace(), obj.GetName())
}

func unstructuredToRuleBinding(obj *unstructured.Unstructured) (*types.RuntimeAlertRuleBinding, error) {
	bytes, err := obj.MarshalJSON()
	if err != nil {
		return nil, err
	}

	var runtimeAlertRuleBindingObj *types.RuntimeAlertRuleBinding
	err = json.Unmarshal(bytes, &runtimeAlertRuleBindingObj)
	if err != nil {
		return nil, err
	}
	return runtimeAlertRuleBindingObj, nil
}
func unstructuredToPod(obj *unstructured.Unstructured) (*corev1.Pod, error) {
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
