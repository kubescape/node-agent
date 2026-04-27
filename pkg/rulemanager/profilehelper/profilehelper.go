package profilehelper

import (
	"errors"

	"github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	corev1 "k8s.io/api/core/v1"
)

// GetContainerProfile returns the ContainerProfile for a containerID plus its
// SyncChecksumMetadataKey annotation. This is the forward API; legacy callers
// go through the shims below until step 6c deletes them.
func GetContainerProfile(objectCache objectcache.ObjectCache, containerID string) (*v1beta1.ContainerProfile, string, error) {
	cpc := objectCache.ContainerProfileCache()
	if cpc == nil {
		return nil, "", errors.New("no container profile cache available")
	}
	cp := cpc.GetContainerProfile(containerID)
	if cp == nil {
		return nil, "", errors.New("no profile available")
	}
	return cp, cp.Annotations[helpers.SyncChecksumMetadataKey], nil
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

