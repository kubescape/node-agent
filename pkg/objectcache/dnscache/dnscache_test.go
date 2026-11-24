package dnscache

import (
	"testing"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubDNSResolver struct {
	entries map[string]string
}

func (s *stubDNSResolver) ResolveIPAddress(containerID string, ipAddr string) (string, bool) {
	domain, ok := s.entries[containerID+"/"+ipAddr]
	return domain, ok
}

func (s *stubDNSResolver) ResolveContainerProcessToCloudServices(_ string, _ uint32) mapset.Set[string] {
	return nil
}

func TestDnsCacheImpl_ResolveIpToDomain(t *testing.T) {
	// Nil resolver returns empty string safely
	nilCache := NewDnsCache(nil)
	require.NotNil(t, nilCache)
	assert.Equal(t, "", nilCache.ResolveIpToDomain("cid-1", "10.0.0.1"))

	resolver := &stubDNSResolver{
		entries: map[string]string{
			"cid-1/93.184.216.34": "example.com.",
		},
	}
	cache := NewDnsCache(resolver)
	require.NotNil(t, cache)

	// Known container and IP
	assert.Equal(t, "example.com.", cache.ResolveIpToDomain("cid-1", "93.184.216.34"))

	// Unknown IP or container returns empty string
	assert.Equal(t, "", cache.ResolveIpToDomain("cid-1", "1.1.1.1"))
	assert.Equal(t, "", cache.ResolveIpToDomain("cid-2", "93.184.216.34"))
}
