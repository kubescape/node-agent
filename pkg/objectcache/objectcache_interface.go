package objectcache

type ObjectCache interface {
	IsCached(kind, namespace, name string) bool
	K8sObjectCache() K8sObjectCache
	ApplicationProfileCache() ApplicationProfileCache
	NetworkNeighborsCache() NetworkNeighborsCache
}

var _ ObjectCache = (*ObjectCacheMock)(nil)

type ObjectCacheMock struct {
}

func NewObjectCacheMock() *ObjectCacheMock {
	return &ObjectCacheMock{}
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

func (om *ObjectCacheMock) IsCached(kind, namespace, name string) bool {
	return true
}
