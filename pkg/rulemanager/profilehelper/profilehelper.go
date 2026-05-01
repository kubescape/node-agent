package profilehelper

import (
	"errors"

	"github.com/kubescape/node-agent/pkg/objectcache"
	corev1 "k8s.io/api/core/v1"
)

// GetProjectedContainerProfile returns the ProjectedContainerProfile for a containerID plus its
// SyncChecksum annotation value.
func GetProjectedContainerProfile(objectCache objectcache.ObjectCache, containerID string) (*objectcache.ProjectedContainerProfile, string, error) {
	cpc := objectCache.ContainerProfileCache()
	if cpc == nil {
		return nil, "", errors.New("no container profile cache available")
	}
	pcp := cpc.GetProjectedContainerProfile(containerID)
	if pcp == nil {
		return nil, "", errors.New("no profile available")
	}
	return pcp, pcp.SyncChecksum, nil
}

func GetContainerName(objectCache objectcache.ObjectCache, containerID string) string {
	sharedData := objectCache.K8sObjectCache().GetSharedContainerData(containerID)
	if sharedData == nil {

		return ""
	}

	containerInfos, exists := sharedData.ContainerInfos[sharedData.ContainerType]
	if !exists || len(containerInfos) == 0 {
		return ""
	}

	return containerInfos[sharedData.ContainerIndex].Name
}

func GetPodSpec(objectCache objectcache.ObjectCache, containerID string) (*corev1.PodSpec, error) {
	sharedData := objectCache.K8sObjectCache().GetSharedContainerData(containerID)
	if sharedData == nil {
		return nil, errors.New("shared data not found")
	}

	podSpec := objectCache.K8sObjectCache().GetPodSpec(sharedData.Namespace, sharedData.PodName)
	if podSpec == nil {
		return nil, errors.New("pod spec not found")
	}

	return podSpec, nil
}
