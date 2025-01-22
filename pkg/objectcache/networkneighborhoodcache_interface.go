package objectcache

import (
	"context"

	"github.com/kubescape/node-agent/pkg/watcher"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
)

type NetworkNeighborhoodCache interface {
	GetNetworkNeighborhood(containerID string) *v1beta1.NetworkNeighborhood
	WatchResources() []watcher.WatchResource
	AddHandler(ctx context.Context, obj runtime.Object)
	ModifyHandler(ctx context.Context, obj runtime.Object)
	DeleteHandler(ctx context.Context, obj runtime.Object)
}

var _ NetworkNeighborhoodCache = (*NetworkNeighborhoodCacheMock)(nil)

type NetworkNeighborhoodCacheMock struct {
}

func (ap *NetworkNeighborhoodCacheMock) GetNetworkNeighborhood(_ string) *v1beta1.NetworkNeighborhood {
	return nil
}

func (ap *NetworkNeighborhoodCacheMock) WatchResources() []watcher.WatchResource {
	return nil
}

func (ap *NetworkNeighborhoodCacheMock) AddHandler(_ context.Context, _ runtime.Object) {
	return
}

func (ap *NetworkNeighborhoodCacheMock) ModifyHandler(_ context.Context, _ runtime.Object) {
	return
}

func (ap *NetworkNeighborhoodCacheMock) DeleteHandler(_ context.Context, _ runtime.Object) {
	return
}
