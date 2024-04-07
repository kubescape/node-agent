package objectcache

import "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"

type NetworkNeighborsCache interface {
	IsCached(kind, namespace, name string) bool
	GetNetworkNeighbors(namespace, podName string) *v1beta1.NetworkNeighbors
}

var _ NetworkNeighborsCache = (*NetworkNeighborsCacheMock)(nil)

type NetworkNeighborsCacheMock struct {
}

func (np *NetworkNeighborsCacheMock) GetNetworkNeighbors(namespace, name string) *v1beta1.NetworkNeighbors {
	return nil
}
func (np *NetworkNeighborsCacheMock) IsCached(kind, namespace, name string) bool {
	return true
}
