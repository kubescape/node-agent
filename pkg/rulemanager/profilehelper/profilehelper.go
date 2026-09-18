package profilehelper

import (
	"errors"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/utils"
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

// GetPodSpec returns the Kubernetes pod spec associated with containerID's
// shared container data. For the host pseudo-container, which has no real
// backing Pod, it returns an explicitly empty PodSpec rather than attempting
// a lookup that would always miss.
func GetPodSpec(objectCache objectcache.ObjectCache, containerID string) (*corev1.PodSpec, error) {
	sharedData := objectCache.K8sObjectCache().GetSharedContainerData(containerID)
	if sharedData == nil {
		return nil, errors.New("shared data not found")
	}

	// The host pseudo-container has synthetic shared data (Namespace "host",
	// PodName "host-<hostID>") that is not backed by any real Kubernetes Pod.
	// Looking it up would always miss and surface as "pod spec not found",
	// which reads like a transient error. Return an explicitly empty pod spec
	// instead: callers iterate podSpec.Containers, so an empty spec means
	// "nothing declared in a pod spec", which is exactly true for the host.
	if utils.IsHost(containerID) {
		return &corev1.PodSpec{}, nil
	}

	podSpec := objectCache.K8sObjectCache().GetPodSpec(sharedData.Namespace, sharedData.PodName)
	if podSpec == nil {
		return nil, errors.New("pod spec not found")
	}

	return podSpec, nil
}
