package containerprofilecache

import (
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/networkpeer"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
)

// genLister is a cluster view whose generation the test drives directly.
type genLister struct{ gen int64 }

func (g *genLister) ServiceByName(string, string) (*networkpeer.ServiceInfo, bool) { return nil, false }
func (g *genLister) ServicesByLabels(map[string]string, map[string]string) []*networkpeer.ServiceInfo {
	return nil
}
func (g *genLister) HostIPs() []string { return nil }
func (g *genLister) Generation() int64 { return g.gen }

type testObjCacheDouble struct {
	objectcache.ObjectCacheMock
	cpc objectcache.ContainerProfileCache
}

func (m *testObjCacheDouble) ContainerProfileCache() objectcache.ContainerProfileCache {
	return m.cpc
}

type testCPCacheDouble struct {
	objectcache.ContainerProfileCacheMock
	profile *objectcache.ProjectedContainerProfile
}

func (m *testCPCacheDouble) GetProjectedContainerProfile(string) *objectcache.ProjectedContainerProfile {
	return m.profile
}

// TestProjectedResolvedGenFeedsCacheKey: the CEL result cache keys on the
// projected profile's SpecHash+SyncChecksum+ResolvedGen. Re-resolving against a
// moved cluster view changes neither of the first two — an authored profile
// carries no SyncChecksum at all — so without ResolvedGen a result computed
// before the informers filled (e.g. "this address is not in egress") would be
// served from cache forever, and the profile's own re-projection would never
// take effect.
func TestProjectedResolvedGenFeedsCacheKey(t *testing.T) {
	l := &genLister{gen: 7}
	c := &ContainerProfileCacheImpl{}
	c.SetServiceLister(l)

	if got := c.listerGen(); got != 7 {
		t.Fatalf("listerGen: got %d want 7", got)
	}

	cpc := &testCPCacheDouble{
		profile: &objectcache.ProjectedContainerProfile{SpecHash: "spec", ResolvedGen: c.listerGen()},
	}
	oc := &testObjCacheDouble{cpc: cpc}

	hasher := cache.HashForContainerProfile(oc)
	args := []ref.Val{types.String("cont1")}
	beforeKey := hasher(args)

	l.gen = 8
	cpc.profile = &objectcache.ProjectedContainerProfile{SpecHash: "spec", ResolvedGen: c.listerGen()}
	afterKey := hasher(args)

	if beforeKey == "" || afterKey == "" {
		t.Fatalf("expected non-empty cache keys, got before=%q after=%q", beforeKey, afterKey)
	}
	if beforeKey == afterKey {
		t.Errorf("cache key must change when the profile is re-resolved against a moved cluster view: before=%q after=%q", beforeKey, afterKey)
	}
}
