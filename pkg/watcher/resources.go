package watcher

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type WatchResources interface {
	WatchResources() []WatchResource
}

var _ WatchResources = &WatchResourcesMock{}

type WatchResourcesMock struct{}

func (rm *WatchResourcesMock) WatchResources() []WatchResource {
	return []WatchResource{&WatchResourceMock{}}
}

type WatchResource interface {
	GroupVersionResource() schema.GroupVersionResource
	ListOptions() metav1.ListOptions
}

var _ WatchResource = &WatchResourceMock{}

type WatchResourceMock struct {
	ListOpt metav1.ListOptions
	Schema  schema.GroupVersionResource
}

func (rm *WatchResourceMock) GroupVersionResource() schema.GroupVersionResource {
	return rm.Schema
}
func (rm *WatchResourceMock) ListOptions() metav1.ListOptions {
	return rm.ListOpt
}

var _ WatchResource = &WatchResourceImpl{}

type WatchResourceImpl struct {
	listOptions          metav1.ListOptions
	groupVersionResource schema.GroupVersionResource
}

func NewWatchResource(groupVersionResource schema.GroupVersionResource, listOptions metav1.ListOptions) *WatchResourceImpl {
	return &WatchResourceImpl{
		groupVersionResource: groupVersionResource,
		listOptions:          listOptions,
	}
}
func (wr *WatchResourceImpl) GroupVersionResource() schema.GroupVersionResource {
	return wr.groupVersionResource
}
func (wr *WatchResourceImpl) ListOptions() metav1.ListOptions {
	return wr.listOptions
}
