package watcher

import (
	"context"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type Adaptor interface {
	WatchResources
	Watcher
}

type Watcher interface {
	AddHandler(ctx context.Context, obj *unstructured.Unstructured)
	ModifyHandler(ctx context.Context, obj *unstructured.Unstructured)
	DeleteHandler(ctx context.Context, obj *unstructured.Unstructured)
}

var _ Watcher = &WatcherMock{}

type WatcherMock struct {
	Added   chan *unstructured.Unstructured
	Updated chan *unstructured.Unstructured
	Deleted chan *unstructured.Unstructured
}

func NewWatcherMock() *WatcherMock {
	return &WatcherMock{
		Added:   make(chan *unstructured.Unstructured),
		Updated: make(chan *unstructured.Unstructured),
		Deleted: make(chan *unstructured.Unstructured),
	}
}
func (wm *WatcherMock) AddHandler(_ context.Context, obj *unstructured.Unstructured) {
	wm.Added <- obj
}

func (wm *WatcherMock) ModifyHandler(_ context.Context, obj *unstructured.Unstructured) {
	wm.Updated <- obj
}

func (wm *WatcherMock) DeleteHandler(_ context.Context, obj *unstructured.Unstructured) {
	wm.Deleted <- obj
}

var _ Adaptor = &AdaptorMock{}

type AdaptorMock struct {
	WatcherMock
	WatchResource []WatchResourceMock
}

func (am *AdaptorMock) WatchResources() []WatchResource {
	w := []WatchResource{}
	for _, wr := range am.WatchResource {
		w = append(w, &wr)
	}
	return w
}
