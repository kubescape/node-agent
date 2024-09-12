package watcher

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
)

type Adaptor interface {
	WatchResources
	Watcher
}

type Watcher interface {
	AddHandler(ctx context.Context, obj runtime.Object)
	ModifyHandler(ctx context.Context, obj runtime.Object)
	DeleteHandler(ctx context.Context, obj runtime.Object)
}

var _ Watcher = &WatcherMock{}

type WatcherMock struct {
	Added   chan runtime.Object
	Updated chan runtime.Object
	Deleted chan runtime.Object
}

func NewWatcherMock() *WatcherMock {
	return &WatcherMock{
		Added:   make(chan runtime.Object),
		Updated: make(chan runtime.Object),
		Deleted: make(chan runtime.Object),
	}
}
func (wm *WatcherMock) AddHandler(_ context.Context, obj runtime.Object) {
	wm.Added <- obj
}

func (wm *WatcherMock) ModifyHandler(_ context.Context, obj runtime.Object) {
	wm.Updated <- obj
}

func (wm *WatcherMock) DeleteHandler(_ context.Context, obj runtime.Object) {
	wm.Deleted <- obj
}

var _ Adaptor = &AdaptorMock{}

type AdaptorMock struct {
	WatcherMock
	WatchResource []WatchResourceMock
}

func (am *AdaptorMock) WatchResources() []WatchResource {
	var w []WatchResource
	for i := range am.WatchResource {
		w = append(w, &am.WatchResource[i])
	}
	return w
}
