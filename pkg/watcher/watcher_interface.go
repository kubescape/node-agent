package watcher

import (
	"k8s.io/apimachinery/pkg/runtime"
)

type Watcher interface {
	RuntimeObjAddHandler(obj runtime.Object)
	RuntimeObjUpdateHandler(obj runtime.Object)
	RuntimeObjDeleteHandler(obj runtime.Object)
}
