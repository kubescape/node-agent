package cache

import (
	"strconv"
	"strings"

	typesv1 "github.com/kubescape/node-agent/pkg/rulebindingmanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/node-agent/pkg/watcher"

	k8sruntime "k8s.io/apimachinery/pkg/runtime"

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

func uniqueName(obj metav1.Object) string {
	return utils.CreateK8sPodID(obj.GetNamespace(), obj.GetName())
}

func unstructuredToRuleBinding(obj *unstructured.Unstructured) (*typesv1.RuntimeAlertRuleBinding, error) {
	rb := &typesv1.RuntimeAlertRuleBinding{}

	objCopy := obj.DeepCopy()
	// severity may be stored as int64 in the CRD but the Go type is string; coerce it
	if rules, ok, _ := unstructured.NestedSlice(objCopy.Object, "spec", "rules"); ok {
		for i, r := range rules {
			rule, ok := r.(map[string]any)
			if !ok {
				continue
			}
			switch v := rule["severity"].(type) {
			case int64:
				rule["severity"] = strconv.FormatInt(v, 10)
				rules[i] = rule
			case float64:
				rule["severity"] = strconv.FormatInt(int64(v), 10)
				rules[i] = rule
			}
		}
		_ = unstructured.SetNestedSlice(objCopy.Object, rules, "spec", "rules")
	}

	if err := k8sruntime.DefaultUnstructuredConverter.FromUnstructured(objCopy.Object, rb); err != nil {
		return nil, err
	}
	return rb, nil
}

func resourcesToWatch(nodeName string, ignoreRuleBindings bool) []watcher.WatchResource {
	var w []watcher.WatchResource

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

	// When rule bindings are ignored, all rules apply to all pods, so there is no
	// reason to watch (and react to) RuntimeAlertRuleBinding objects.
	if !ignoreRuleBindings {
		// add rule binding
		rb := watcher.NewWatchResource(typesv1.RuleBindingAlertGvr, metav1.ListOptions{})
		w = append(w, rb)
	}

	return w
}
