package objectcache

type ObjectCache interface {
	K8sObjectCache() K8sObjectCache
	ApplicationProfileCache() ApplicationProfileCache
	NetworkNeighborhoodCache() NetworkNeighborhoodCache
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
func (om *ObjectCacheMock) NetworkNeighborhoodCache() NetworkNeighborhoodCache {
	return &NetworkNeighborhoodCacheMock{}
}
