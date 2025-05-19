package rulemanager

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/objectcache"
)

func IsProfileExists(objCache objectcache.ObjectCache, containerID string, profileType armotypes.ProfileType) bool {
	switch profileType {
	case armotypes.ApplicationProfile:
		ap := objCache.ApplicationProfileCache().GetApplicationProfile(containerID)
		return ap != nil

	case armotypes.NetworkProfile:
		nn := objCache.NetworkNeighborhoodCache().GetNetworkNeighborhood(containerID)
		return nn != nil

	default:
		return false
	}
}
