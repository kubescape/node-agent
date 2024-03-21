package networkneighborscache

import (
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/ruleengine/objectcache"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

var _ objectcache.NetworkNeighborsCache = (*NetworkNeighborsCacheImp)(nil)

type NetworkNeighborsCacheImp struct {
	k8sClient k8sclient.K8sClientInterface
}

func NewNetworkNeighborsCache(k8sClient k8sclient.K8sClientInterface) (*NetworkNeighborsCacheImp, error) {
	return &NetworkNeighborsCacheImp{
		k8sClient: k8sClient,
	}, nil

}

func (np *NetworkNeighborsCacheImp) GetNetworkNeighbors(namespace, name string) *v1beta1.NetworkNeighbors {
	// TODO: implement
	return nil
}
