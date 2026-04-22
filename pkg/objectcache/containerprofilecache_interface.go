// Package objectcache defines interfaces for the node-agent object cache layer.
package objectcache

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/objectcache/applicationprofilecache/callstackcache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type ContainerProfileCache interface {
	GetContainerProfile(containerID string) *v1beta1.ContainerProfile
	GetContainerProfileState(containerID string) *ProfileState
	GetCallStackSearchTree(containerID string) *callstackcache.CallStackSearchTree
	ContainerCallback(notif containercollection.PubSubEvent)
}

var _ ContainerProfileCache = (*ContainerProfileCacheMock)(nil)

type ContainerProfileCacheMock struct{}

func (cp *ContainerProfileCacheMock) GetContainerProfile(_ string) *v1beta1.ContainerProfile {
	return nil
}

func (cp *ContainerProfileCacheMock) GetContainerProfileState(_ string) *ProfileState {
	return nil
}

func (cp *ContainerProfileCacheMock) GetCallStackSearchTree(_ string) *callstackcache.CallStackSearchTree {
	return nil
}

func (cp *ContainerProfileCacheMock) ContainerCallback(_ containercollection.PubSubEvent) {
}
