package objectcache

import (
	"github.com/kubescape/node-agent/pkg/objectcache"
)

var _ objectcache.ObjectCache = (*ObjectCacheImpl)(nil)

type ObjectCacheImpl struct {
	k  objectcache.K8sObjectCache
	ap objectcache.ApplicationProfileCache
	np objectcache.NetworkNeighborhoodCache
}

func NewObjectCache(k objectcache.K8sObjectCache, ap objectcache.ApplicationProfileCache, np objectcache.NetworkNeighborhoodCache) *ObjectCacheImpl {
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
func (o *ObjectCacheImpl) NetworkNeighborhoodCache() objectcache.NetworkNeighborhoodCache {
	return o.np
}
