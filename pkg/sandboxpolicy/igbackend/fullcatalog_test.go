package igbackend

import (
	"fmt"
	"math"
	"sync"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

func catalogCandidate(t *testing.T, generation uint64) (sandboxpolicy.Plan, *fullpolicy.KernelProgram) {
	t.Helper()
	p := verdictPlan()
	p.Revision = fmt.Sprintf("revision-%d", generation)
	p.Policies[0].Exec.Rules[0].Name = fmt.Sprintf("rule-%d", generation)
	k, err := CompileFull(sandboxpolicy.Binding{ContainerName: "app"}, p, generation, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p, k
}
func catalogRaw(generation uint64) RawFullVerdict {
	return RawFullVerdict{RawVerdict: RawVerdict{Generation: generation, Cgroup: 19, Mode: 2}, MatchedRules: [4]uint64{1}}
}
func newTestCatalog() *FullVerdictCatalog {
	return NewFullVerdictCatalog(sandboxpolicy.Binding{CgroupID: 19, ContainerName: "app"})
}
func stageCatalog(t *testing.T, c *FullVerdictCatalog, generation uint64) {
	t.Helper()
	p, k := catalogCandidate(t, generation)
	if err := c.Stage(generation, p, k); err != nil {
		t.Fatal(err)
	}
}
func assertCatalogDecode(t *testing.T, c *FullVerdictCatalog, generation uint64) {
	t.Helper()
	v, err := c.Decode(catalogRaw(generation))
	if err != nil || v.Revision != fmt.Sprintf("revision-%d", generation) || v.Rule != fmt.Sprintf("rule-%d", generation) {
		t.Fatalf("generation %d: wrong provenance %+v, %v", generation, v, err)
	}
}

func TestFullCatalogPublication(t *testing.T) {
	c := newTestCatalog()
	stageCatalog(t, c, 1)
	assertCatalogDecode(t, c, 1) // Kernel can emit before Go receives commit.
	if err := c.Commit(1); err != nil {
		t.Fatal(err)
	}
	stageCatalog(t, c, 2)
	assertCatalogDecode(t, c, 1)
	assertCatalogDecode(t, c, 2)
	p, k := catalogCandidate(t, 3)
	if err := c.Stage(3, p, k); err == nil {
		t.Fatal("accepted two pending publications")
	}
	if err := c.Commit(3); err == nil {
		t.Fatal("committed an unstaged generation")
	}
	if err := c.Abort(1); err == nil {
		t.Fatal("aborted active provenance")
	}
	if err := c.Abort(2); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Decode(catalogRaw(2)); err == nil {
		t.Fatal("decoded aborted publication")
	}
	assertCatalogDecode(t, c, 1)
	if err := c.Stage(2, p, k); err == nil {
		t.Fatal("reused aborted generation")
	}
	if err := c.Stage(3, p, k); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(3); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(3); err != nil {
		t.Fatal("commit retry failed", err)
	}
	if err := c.Abort(3); err == nil {
		t.Fatal("aborted partially finalized kernel commit")
	}
	assertCatalogDecode(t, c, 1) // Delayed events retain old rule names.
	assertCatalogDecode(t, c, 3)
	stageCatalog(t, c, 4)
	if err := c.Commit(3); err != nil {
		t.Fatal(err)
	}
	if c.pending != 4 {
		t.Fatal("stale idempotent commit affected newer proposal")
	}
	if err := c.Abort(3); err == nil {
		t.Fatal("stale abort affected newer proposal")
	}
	if c.pending != 4 {
		t.Fatal("stale abort cleared pending")
	}
}

func TestFullCatalogValidationAndSnapshots(t *testing.T) {
	c := newTestCatalog()
	stageCatalog(t, c, 1)
	if err := c.Commit(1); err != nil {
		t.Fatal(err)
	}
	p, k := catalogCandidate(t, 2)
	if err := c.Stage(2, p, nil); err == nil {
		t.Fatal("accepted nil program")
	}
	if err := c.Stage(2, p, k); err == nil {
		t.Fatal("reused failed validation attempt")
	}
	if err := c.Stage(3, p, k); err == nil {
		t.Fatal("accepted different IR generation")
	}
	p, k = catalogCandidate(t, 4)
	if err := c.Stage(4, p, k); err != nil {
		t.Fatal(err)
	}
	p.Revision = "mutated"
	p.Policies[0].Exec.Rules[0].Name = "mutated"
	k.Rules[0].Name = "mutated"
	k.Entries[0][0] = 0
	assertCatalogDecode(t, c, 1)
	assertCatalogDecode(t, c, 4)
	raw := catalogRaw(4)
	raw.Cgroup++
	if _, err := c.Decode(raw); err == nil {
		t.Fatal("accepted wrong binding cgroup")
	}
	if _, err := c.Decode(catalogRaw(100)); err == nil {
		t.Fatal("decoded unknown generation")
	}
	if err := c.Abort(4); err != nil {
		t.Fatal(err)
	}
	// Reserved/invalid maximum still consumes its attempt and cannot wrap.
	if err := c.Stage(math.MaxUint64, p, nil); err == nil {
		t.Fatal("accepted invalid maximum")
	}
	if err := c.Stage(0, p, k); err == nil {
		t.Fatal("wrapped generation")
	}
	if err := c.Stage(5, p, k); err == nil {
		t.Fatal("reset attempt watermark")
	}
	assertCatalogDecode(t, c, 1)
}

func TestFullCatalogBoundedHistory(t *testing.T) {
	c := newTestCatalog()
	for g := uint64(1); g <= FullVerdictCatalogCapacity+3; g++ {
		stageCatalog(t, c, g)
		if len(c.decoders) > FullVerdictCatalogCapacity {
			t.Fatal("unbounded provenance")
		}
		if err := c.Commit(g); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Decode(catalogRaw(1)); err == nil {
		t.Fatal("decoded evicted generation")
	}
	active := uint64(FullVerdictCatalogCapacity + 3)
	for g := active + 1; g < active+FullVerdictCatalogCapacity*2; g++ {
		stageCatalog(t, c, g)
		assertCatalogDecode(t, c, active)
		if err := c.Abort(g); err != nil {
			t.Fatal(err)
		}
		assertCatalogDecode(t, c, active)
	}
	if c.active != active || len(c.decoders) > FullVerdictCatalogCapacity {
		t.Fatal("failed proposals displaced active")
	}
}

func TestFullCatalogConcurrentReads(t *testing.T) {
	c := newTestCatalog()
	stageCatalog(t, c, 1)
	if err := c.Commit(1); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				assertCatalogDecode(t, c, 1)
			}
		}()
	}
	for g := uint64(2); g < 40; g++ {
		stageCatalog(t, c, g)
		if err := c.Abort(g); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}
