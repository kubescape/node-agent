package objectcache

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/objectcache"

	"github.com/stretchr/testify/assert"
)

func TestK8sObjectCache(t *testing.T) {
	k := &objectcache.K8sObjectCacheMock{}
	k8sObjectCache := NewObjectCache(k, nil, nil)
	assert.NotNil(t, k8sObjectCache.K8sObjectCache())
}

func TestContainerProfileCache(t *testing.T) {
	cp := &objectcache.ContainerProfileCacheMock{}
	k8sObjectCache := NewObjectCache(nil, cp, nil)
	assert.NotNil(t, k8sObjectCache.ContainerProfileCache())
}
