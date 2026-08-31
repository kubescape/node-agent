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

func TestRuleObjectCacheMock_ResolveIpToDomain(t *testing.T) {
	mock := &RuleObjectCacheMock{}
	mock.SetDnsCache(map[string]string{
		"cont-1:1.2.3.4": "scoped-domain.com",
		"5.6.7.8":        "global-domain.com",
	})

	// Test container-scoped resolution
	assert.Equal(t, "scoped-domain.com", mock.ResolveIpToDomain("cont-1", "1.2.3.4"))
	// Test container with fallback to unscoped key
	assert.Equal(t, "global-domain.com", mock.ResolveIpToDomain("cont-2", "5.6.7.8"))
	// Test unscoped lookup
	assert.Equal(t, "global-domain.com", mock.ResolveIpToDomain("", "5.6.7.8"))
	// Test missing resolution
	assert.Equal(t, "", mock.ResolveIpToDomain("cont-1", "9.9.9.9"))
}
