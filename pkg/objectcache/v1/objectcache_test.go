package objectcache

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/objectcache"

	"github.com/stretchr/testify/assert"
)

func TestK8sObjectCache(t *testing.T) {
	k := &objectcache.K8sObjectCacheMock{}
	k8sObjectCache := NewObjectCache(k, nil, nil, nil, nil)
	assert.NotNil(t, k8sObjectCache.K8sObjectCache())
}

func TestApplicationProfileCache(t *testing.T) {
	ap := &objectcache.ApplicationProfileCacheMock{}
	k8sObjectCache := NewObjectCache(nil, ap, nil, nil, nil)
	assert.NotNil(t, k8sObjectCache.ApplicationProfileCache())
}

func TestNetworkNeighborhoodCache(t *testing.T) {
	nn := &objectcache.NetworkNeighborhoodCacheMock{}
	k8sObjectCache := NewObjectCache(nil, nil, nn, nil, nil)
	assert.NotNil(t, k8sObjectCache.NetworkNeighborhoodCache())
}

func TestContainerProfileCache(t *testing.T) {
	cp := &objectcache.ContainerProfileCacheMock{}
	k8sObjectCache := NewObjectCache(nil, nil, nil, cp, nil)
	assert.NotNil(t, k8sObjectCache.ContainerProfileCache())
}
