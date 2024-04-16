package objectcache

import (
	"node-agent/pkg/objectcache"
)

var _ objectcache.ObjectCache = (*ObjectCacheImpl)(nil)

type ObjectCacheImpl struct {
	k  objectcache.K8sObjectCache
	ap objectcache.ApplicationProfileCache
	np objectcache.NetworkNeighborsCache
}

func NewObjectCache(k objectcache.K8sObjectCache, ap objectcache.ApplicationProfileCache, np objectcache.NetworkNeighborsCache) *ObjectCacheImpl {
	return &ObjectCacheImpl{
		k:  k,
		ap: ap,
		np: np,
	}
}

func (o *ObjectCacheImpl) K8sObjectCache() objectcache.K8sObjectCache {
	return o.k
}

func (o *ObjectCacheImpl) ApplicationProfileCache() objectcache.ApplicationProfileCache {
	return o.ap
}
func (o *ObjectCacheImpl) NetworkNeighborsCache() objectcache.NetworkNeighborsCache {
	return o.np
}
