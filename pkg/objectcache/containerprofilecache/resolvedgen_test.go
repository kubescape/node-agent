package containerprofilecache

import (
	"strconv"
	"testing"

	"github.com/kubescape/node-agent/pkg/networkpeer"
	"github.com/kubescape/node-agent/pkg/objectcache"
)

// genLister is a cluster view whose generation the test drives directly.
type genLister struct{ gen int64 }

func (g *genLister) ServiceByName(string, string) (*networkpeer.ServiceInfo, bool) { return nil, false }
func (g *genLister) ServicesByLabels(map[string]string, map[string]string) []*networkpeer.ServiceInfo {
	return nil
}
func (g *genLister) HostIPs() []string { return nil }
func (g *genLister) Generation() int64 { return g.gen }

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

	key := func(p *objectcache.ProjectedContainerProfile) string {
		return p.SpecHash + "|" + p.SyncChecksum + "|" + strconv.FormatInt(p.ResolvedGen, 10)
	}
	before := &objectcache.ProjectedContainerProfile{SpecHash: "spec", ResolvedGen: c.listerGen()}

	l.gen = 8
	after := &objectcache.ProjectedContainerProfile{SpecHash: "spec", ResolvedGen: c.listerGen()}

	if key(before) == key(after) {
		t.Errorf("cache key must change when the profile is re-resolved against a moved cluster view")
	}
}
