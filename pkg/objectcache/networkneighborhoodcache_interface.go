package objectcache

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type NetworkNeighborhoodCache interface {
	GetNetworkNeighborhood(containerID string) *v1beta1.NetworkNeighborhood
	ContainerCallback(notif containercollection.PubSubEvent)
}

var _ NetworkNeighborhoodCache = (*NetworkNeighborhoodCacheMock)(nil)

type NetworkNeighborhoodCacheMock struct {
}

func (nn *NetworkNeighborhoodCacheMock) GetNetworkNeighborhood(_ string) *v1beta1.NetworkNeighborhood {
	return nil
}

func (nn *NetworkNeighborhoodCacheMock) ContainerCallback(_ containercollection.PubSubEvent) {
}
