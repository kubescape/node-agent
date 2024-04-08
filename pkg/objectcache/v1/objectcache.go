package objectcache

import (
	"github.com/kubescape/node-agent/pkg/objectcache"
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

func (o *ObjectCacheImpl) IsCached(kind, namespace, name string) bool {
	if !o.k.IsCached(kind, namespace, name) {
		return false
	}
	if !o.ap.IsCached(kind, namespace, name) {
		return false
	}
	if !o.np.IsCached(kind, namespace, name) {
		return false
	}
	return true
}
