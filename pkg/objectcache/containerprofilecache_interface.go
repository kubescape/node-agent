// Package objectcache defines interfaces for the node-agent object cache layer.
package objectcache

import (
	"context"
	"errors"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/objectcache/callstackcache"
)

// ContainerProfileCache is the interface satisfied by ContainerProfileCacheImpl
// and its test mocks. GetProjectedContainerProfile replaces the former
// GetContainerProfile — callers receive the compact projected form instead of
// the raw CRD pointer.
type ContainerProfileCache interface {
	GetProjectedContainerProfile(containerID string) *ProjectedContainerProfile
	GetContainerProfileState(containerID string) *ProfileState
	GetCallStackSearchTree(containerID string) *callstackcache.CallStackSearchTree
	SetProjectionSpec(spec RuleProjectionSpec)
	ContainerCallback(notif containercollection.PubSubEvent)
	Start(ctx context.Context)
}

var _ ContainerProfileCache = (*ContainerProfileCacheMock)(nil)

type ContainerProfileCacheMock struct{}

func (cp *ContainerProfileCacheMock) GetProjectedContainerProfile(_ string) *ProjectedContainerProfile {
	return nil
}

func (cp *ContainerProfileCacheMock) GetContainerProfileState(_ string) *ProfileState {
	return &ProfileState{Error: errors.New("mock: profile not found")}
}

func (cp *ContainerProfileCacheMock) GetCallStackSearchTree(_ string) *callstackcache.CallStackSearchTree {
	return nil
}

func (cp *ContainerProfileCacheMock) SetProjectionSpec(_ RuleProjectionSpec) {}

func (cp *ContainerProfileCacheMock) ContainerCallback(_ containercollection.PubSubEvent) {}

func (cp *ContainerProfileCacheMock) Start(_ context.Context) {}
