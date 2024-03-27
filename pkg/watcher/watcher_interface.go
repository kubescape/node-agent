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
	Added   []*unstructured.Unstructured
	Updated []*unstructured.Unstructured
	Deleted []*unstructured.Unstructured
}

func (wm *WatcherMock) AddHandler(_ context.Context, obj *unstructured.Unstructured) {
	wm.Added = append(wm.Added, obj)
}

func (wm *WatcherMock) ModifyHandler(_ context.Context, obj *unstructured.Unstructured) {
	wm.Updated = append(wm.Updated, obj)
}

func (wm *WatcherMock) DeleteHandler(_ context.Context, obj *unstructured.Unstructured) {
	wm.Deleted = append(wm.Deleted, obj)
}
