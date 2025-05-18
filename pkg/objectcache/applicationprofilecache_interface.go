package objectcache

import (
	"context"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/objectcache/applicationprofilecache/callstackcache"
	"github.com/kubescape/node-agent/pkg/watcher"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
)

type ApplicationProfileCache interface {
	GetApplicationProfile(containerID string) *v1beta1.ApplicationProfile
	GetCallStackSearchTree(containerID string) *callstackcache.CallStackSearchTree
	ContainerCallback(notif containercollection.PubSubEvent)
}

var _ ApplicationProfileCache = (*ApplicationProfileCacheMock)(nil)

type ApplicationProfileCacheMock struct {
}

func (ap *ApplicationProfileCacheMock) GetApplicationProfile(_ string) *v1beta1.ApplicationProfile {
	return nil
}

func (ap *ApplicationProfileCacheMock) GetCallStackSearchTree(_ string) *callstackcache.CallStackSearchTree {
	return nil
}

func (ap *ApplicationProfileCacheMock) WatchResources() []watcher.WatchResource {
	return nil
}

func (ap *ApplicationProfileCacheMock) AddHandler(_ context.Context, _ runtime.Object) {
	return
}

func (ap *ApplicationProfileCacheMock) ModifyHandler(_ context.Context, _ runtime.Object) {
	return
}

func (ap *ApplicationProfileCacheMock) DeleteHandler(_ context.Context, _ runtime.Object) {
	return
}

func (ap *ApplicationProfileCacheMock) ContainerCallback(_ containercollection.PubSubEvent) {
	return
}
