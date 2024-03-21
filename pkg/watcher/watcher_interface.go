package watcher

import (
	"k8s.io/apimachinery/pkg/runtime"
)

type Watcher interface {
	RuntimeObjAddHandler(obj runtime.Object)
	RuntimeObjUpdateHandler(obj runtime.Object)
	RuntimeObjDeleteHandler(obj runtime.Object)
}

var _ Watcher = &WatcherMock{}

type WatcherMock struct {
	AddedPods   []runtime.Object
	UpdatedPods []runtime.Object
	DeletedPods []runtime.Object
}

func (wm *WatcherMock) RuntimeObjAddHandler(obj runtime.Object) {
	wm.AddedPods = append(wm.AddedPods, obj)
}
func (wm *WatcherMock) RuntimeObjUpdateHandler(obj runtime.Object) {
	wm.UpdatedPods = append(wm.UpdatedPods, obj)
}
func (wm *WatcherMock) RuntimeObjDeleteHandler(obj runtime.Object) {
	wm.DeletedPods = append(wm.DeletedPods, obj)
}
