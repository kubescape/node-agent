package profilehelper

import (
	"errors"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/ruleprocess"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func GetApplicationProfile(containerID string, objectCache objectcache.ObjectCache) (*v1beta1.ApplicationProfile, error) {
	ap := objectCache.ApplicationProfileCache().GetApplicationProfile(containerID)
	if ap == nil {
		return nil, ruleprocess.NoProfileAvailable
	}
	return ap, nil
}

func GetNetworkNeighborhood(containerID string, objectCache objectcache.ObjectCache) (*v1beta1.NetworkNeighborhood, error) {
	nn := objectCache.NetworkNeighborhoodCache().GetNetworkNeighborhood(containerID)
	if nn == nil {
		return nil, ruleprocess.NoProfileAvailable
	}
	return nn, nil
}

func GetContainerFromApplicationProfile(ap *v1beta1.ApplicationProfile, containerName string) (v1beta1.ApplicationProfileContainer, error) {
	for _, s := range ap.Spec.Containers {
		if s.Name == containerName {
			return s, nil
		}
	}
	for _, s := range ap.Spec.InitContainers {
		if s.Name == containerName {
			return s, nil
		}
	}
	for _, s := range ap.Spec.EphemeralContainers {
		if s.Name == containerName {
			return s, nil
		}
	}
	return v1beta1.ApplicationProfileContainer{}, errors.New("container not found")
}

func GetContainerFromNetworkNeighborhood(nn *v1beta1.NetworkNeighborhood, containerName string) (v1beta1.NetworkNeighborhoodContainer, error) {
	for _, c := range nn.Spec.Containers {
		if c.Name == containerName {
			return c, nil
		}
	}
	for _, c := range nn.Spec.InitContainers {
		if c.Name == containerName {
			return c, nil
		}
	}
	for _, c := range nn.Spec.EphemeralContainers {
		if c.Name == containerName {
			return c, nil
		}
	}
	return v1beta1.NetworkNeighborhoodContainer{}, errors.New("container not found")
}
