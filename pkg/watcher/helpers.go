package watcher

import (
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

// MakeEventKey creates a unique key for an event from a watcher
func MakeEventKey(e watch.Event) string {
	gvk := e.Object.GetObjectKind().GroupVersionKind()
	meta := e.Object.(metav1.Object)
	return strings.Join([]string{gvk.Group, gvk.Version, gvk.Kind, meta.GetNamespace(), meta.GetName()}, "/")
}
