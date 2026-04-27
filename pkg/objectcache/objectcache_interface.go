package objectcache

type ObjectCache interface {
	K8sObjectCache() K8sObjectCache
	ContainerProfileCache() ContainerProfileCache
	DnsCache() DnsCache
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

func (om *ObjectCacheMock) ContainerProfileCache() ContainerProfileCache {
	return &ContainerProfileCacheMock{}
}

func (om *ObjectCacheMock) DnsCache() DnsCache {
	return &DnsCacheMock{}
}
