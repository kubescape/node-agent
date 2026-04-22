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

// GetApplicationProfile returns the legacy ApplicationProfile for compatibility
// with callers that have not yet moved to GetContainerProfile.
//
// Deprecated: removed in step 6c. Prefer GetContainerProfile.
func GetApplicationProfile(containerID string, objectCache objectcache.ObjectCache) (*v1beta1.ApplicationProfile, error) {
	ap := objectCache.ApplicationProfileCache().GetApplicationProfile(containerID)
	if ap == nil {
		return nil, errors.New("no profile available")
	}
	return ap, nil
}

// GetNetworkNeighborhood returns the legacy NetworkNeighborhood for
// compatibility with callers that have not yet moved to GetContainerProfile.
//
// Deprecated: removed in step 6c. Prefer GetContainerProfile.
func GetNetworkNeighborhood(containerID string, objectCache objectcache.ObjectCache) (*v1beta1.NetworkNeighborhood, error) {
	nn := objectCache.NetworkNeighborhoodCache().GetNetworkNeighborhood(containerID)
	if nn == nil {
		return nil, errors.New("no profile available")
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

// GetContainerApplicationProfile synthesizes a per-container
// ApplicationProfileContainer from the unified ContainerProfile for this
// container. Consensus delta #2: this is a CP→legacy-shape field mapping, NOT
// an alias — callers get the same fields they used to read off the legacy AP.
//
// Deprecated: removed in step 6c. Prefer GetContainerProfile.
func GetContainerApplicationProfile(objectCache objectcache.ObjectCache, containerID string) (v1beta1.ApplicationProfileContainer, string, error) {
	cpc := objectCache.ContainerProfileCache()
	if cpc == nil {
		return v1beta1.ApplicationProfileContainer{}, "", errors.New("no container profile cache available")
	}
	cp := cpc.GetContainerProfile(containerID)
	if cp == nil {
		return v1beta1.ApplicationProfileContainer{}, "", errors.New("no profile available")
	}
	containerName := GetContainerName(objectCache, containerID)
	if containerName == "" {
		return v1beta1.ApplicationProfileContainer{}, "", errors.New("container name not found")
	}
	return v1beta1.ApplicationProfileContainer{
		Name:                 containerName,
		Capabilities:         cp.Spec.Capabilities,
		Execs:                cp.Spec.Execs,
		Opens:                cp.Spec.Opens,
		Syscalls:             cp.Spec.Syscalls,
		SeccompProfile:       cp.Spec.SeccompProfile,
		Endpoints:            cp.Spec.Endpoints,
		ImageID:              cp.Spec.ImageID,
		ImageTag:             cp.Spec.ImageTag,
		PolicyByRuleId:       cp.Spec.PolicyByRuleId,
		IdentifiedCallStacks: cp.Spec.IdentifiedCallStacks,
	}, cp.Annotations[helpers.SyncChecksumMetadataKey], nil
}

// GetContainerNetworkNeighborhood synthesizes a per-container
// NetworkNeighborhoodContainer from the unified ContainerProfile for this
// container. Consensus delta #2: CP→legacy-shape field mapping.
//
// Deprecated: removed in step 6c. Prefer GetContainerProfile.
func GetContainerNetworkNeighborhood(objectCache objectcache.ObjectCache, containerID string) (v1beta1.NetworkNeighborhoodContainer, error) {
	cpc := objectCache.ContainerProfileCache()
	if cpc == nil {
		return v1beta1.NetworkNeighborhoodContainer{}, errors.New("no container profile cache available")
	}
	cp := cpc.GetContainerProfile(containerID)
	if cp == nil {
		return v1beta1.NetworkNeighborhoodContainer{}, errors.New("no profile available")
	}
	containerName := GetContainerName(objectCache, containerID)
	if containerName == "" {
		return v1beta1.NetworkNeighborhoodContainer{}, errors.New("container name not found")
	}
	return v1beta1.NetworkNeighborhoodContainer{
		Name:    containerName,
		Ingress: cp.Spec.Ingress,
		Egress:  cp.Spec.Egress,
	}, nil
}
