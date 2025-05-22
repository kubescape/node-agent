package objectcache

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/objectcache/applicationprofilecache/callstackcache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type ApplicationProfileCache interface {
	GetApplicationProfile(containerID string) *v1beta1.ApplicationProfile
	GetApplicationProfileState(containerID string) *ProfileState
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

func (ap *ApplicationProfileCacheMock) ContainerCallback(_ containercollection.PubSubEvent) {
}

func (ap *ApplicationProfileCacheMock) GetApplicationProfileState(_ string) *ProfileState {
	return nil
}
