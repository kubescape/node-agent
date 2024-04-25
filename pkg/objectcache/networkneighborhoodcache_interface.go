package objectcache

import "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"

type NetworkNeighborhoodCache interface {
	GetNetworkNeighborhood(containerID string) *v1beta1.NetworkNeighborhood
}

var _ NetworkNeighborhoodCache = (*NetworkNeighborhoodCacheMock)(nil)

type NetworkNeighborhoodCacheMock struct {
}

func (ap *NetworkNeighborhoodCacheMock) GetNetworkNeighborhood(containerID string) *v1beta1.NetworkNeighborhood {
	return nil
}
