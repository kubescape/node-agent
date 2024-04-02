package objectcache

import (
	"node-agent/pkg/objectcache"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestK8sObjectCache(t *testing.T) {
	k := &objectcache.K8sObjectCacheMock{}
	k8sObjectCache := NewObjectCache(k, nil, nil, nil)
	assert.NotNil(t, k8sObjectCache.K8sObjectCache())
}

func TestApplicationProfileCache(t *testing.T) {
	ap := &objectcache.ApplicationProfileCacheMock{}
	k8sObjectCache := NewObjectCache(nil, ap, nil, nil)
	assert.NotNil(t, k8sObjectCache.ApplicationProfileCache())
}

func TestApplicationActivityCache(t *testing.T) {
	aa := &objectcache.ApplicationActivityCacheMock{}
	k8sObjectCache := NewObjectCache(nil, nil, aa, nil)
	assert.NotNil(t, k8sObjectCache.ApplicationActivityCache())
}

func TestNetworkNeighborsCache(t *testing.T) {
	nn := &objectcache.NetworkNeighborsCacheMock{}
	k8sObjectCache := NewObjectCache(nil, nil, nil, nn)
	assert.NotNil(t, k8sObjectCache.NetworkNeighborsCache())
}
