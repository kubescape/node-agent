package profilevalidator

import (
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilevalidator/profilehelper"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type ProfileRegistryImpl struct {
	objectCache objectcache.ObjectCache
}

func NewProfileRegistry(objectCache objectcache.ObjectCache) ProfileRegistry {
	return &ProfileRegistryImpl{
		objectCache: objectCache,
	}
}

func (r *ProfileRegistryImpl) GetAvailableProfiles(containerName, containerID string) (*v1beta1.ApplicationProfileContainer, *v1beta1.NetworkNeighborhoodContainer, bool) {
	ap, err := profilehelper.GetApplicationProfile(containerID, r.objectCache)
	if err != nil {
		return nil, nil, false
	}
	containerAppProfile, err := profilehelper.GetContainerFromApplicationProfile(ap, containerName)
	if err != nil {
		return nil, nil, false
	}

	nn, err := profilehelper.GetNetworkNeighborhood(containerID, r.objectCache)
	if err != nil {
		return nil, nil, false
	}
	containerNNProfile, err := profilehelper.GetContainerFromNetworkNeighborhood(nn, containerName)
	if err != nil {
		return nil, nil, false
	}

	return &containerAppProfile, &containerNNProfile, true
}
