package objectcache

import (
	"node-agent/pkg/objectcache"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestK8sObjectCache(t *testing.T) {
	k := &objectcache.K8sObjectCacheMock{}
	k8sObjectCache := NewObjectCache(k, nil, nil)
	assert.NotNil(t, k8sObjectCache.K8sObjectCache())
}

func TestApplicationProfileCache(t *testing.T) {
	ap := &objectcache.ApplicationProfileCacheMock{}
	k8sObjectCache := NewObjectCache(nil, ap, nil)
	assert.NotNil(t, k8sObjectCache.ApplicationProfileCache())
}

func TestNetworkNeighborhoodCache(t *testing.T) {
	nn := &objectcache.NetworkNeighborhoodCacheMock{}
	k8sObjectCache := NewObjectCache(nil, nil, nn)
	assert.NotNil(t, k8sObjectCache.NetworkNeighborhoodCache())
}
