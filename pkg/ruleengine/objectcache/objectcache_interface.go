package objectcache

type ObjectCache interface {
	K8sObjectCache() K8sObjectCache
	ApplicationProfileCache() ApplicationProfileCache
	NetworkNeighborsCache() NetworkNeighborsCache
}

var _ ObjectCache = (*ObjectCacheMock)(nil)

type ObjectCacheMock struct {
}

func (om *ObjectCacheMock) K8sObjectCache() K8sObjectCache {
	return &K8sObjectCacheMock{}
}

func (om *ObjectCacheMock) ApplicationProfileCache() ApplicationProfileCache {
	return &ApplicationProfileCacheMock{}
}
func (om *ObjectCacheMock) NetworkNeighborsCache() NetworkNeighborsCache {
	return &NetworkNeighborsCacheMock{}
}
