// Stacking truth table for the effective ruleset: rules from stacked Rules
// fragments are ADDITIVE across distinct (bundle, ID) keys and REPLACEMENT
// within the same key; evaluation prefers the cluster-wide variant when the
// same ID exists in several bundles; a fragment leaving the cluster removes
// exactly its rules on the next sync.
package rulecreator

import (
	"sync"
	"testing"

	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/stretchr/testify/assert"
)

func rule(bundle, id, name string, clusterWide bool) typesv1.Rule {
	return typesv1.Rule{ID: id, Name: name, Bundle: bundle, ClusterWide: clusterWide, Enabled: true}
}

// R-A1: distinct IDs from stacked fragments union into the effective set.
func TestRuleStacking_AdditiveAcrossIDs(t *testing.T) {
	r := NewRuleCreator()
	r.SyncRules([]typesv1.Rule{
		rule("base", "R0001", "exec", false),
		rule("overlay", "R0011", "egress", false),
	})
	assert.Len(t, r.Rules, 2, "distinct (bundle, ID) keys are additive")
}

// R-R1: the same (bundle, ID) appearing twice in one sync collapses to ONE
// rule — the later element replaces the earlier (map overwrite in sync order).
func TestRuleStacking_SameBundleSameIDReplaces(t *testing.T) {
	r := NewRuleCreator()
	r.SyncRules([]typesv1.Rule{
		rule("base", "R0001", "exec-v1", false),
		rule("base", "R0001", "exec-v2", false),
	})
	assert.Len(t, r.Rules, 1, "same (bundle, ID) must collapse to a single rule")
	assert.Equal(t, "exec-v2", r.Rules[0].Name, "the later occurrence replaces the earlier")
}

// R-A2: the same ID stacked from DIFFERENT bundles coexists — bundle-scoped
// variants are distinct keys, not replacements of each other.
func TestRuleStacking_SameIDAcrossBundlesCoexists(t *testing.T) {
	r := NewRuleCreator()
	r.SyncRules([]typesv1.Rule{
		rule("", "R0001", "exec-clusterwide", true),
		rule("tenant-a", "R0001", "exec-a", false),
		rule("tenant-b", "R0001", "exec-b", false),
	})
	assert.Len(t, r.Rules, 3, "same ID across bundles must coexist (multi-stack)")
}

// R-P1: when several stacked variants share an ID, evaluation prefers the
// cluster-wide / bundle-less one, falling back to the first bundle-scoped.
func TestRuleStacking_EvaluationPrefersClusterWide(t *testing.T) {
	r := NewRuleCreator()
	r.SyncRules([]typesv1.Rule{
		rule("tenant-a", "R0001", "exec-a", false),
		rule("", "R0001", "exec-clusterwide", true),
	})
	assert.Equal(t, "exec-clusterwide", r.CreateRuleByID("R0001").Name,
		"cluster-wide variant wins evaluation over bundle-scoped")
	assert.Equal(t, "exec-clusterwide", r.CreateRuleByName("exec-clusterwide").Name)

	r2 := NewRuleCreator()
	r2.SyncRules([]typesv1.Rule{
		rule("tenant-a", "R0001", "exec-a", false),
		rule("tenant-b", "R0001", "exec-b", false),
	})
	assert.Equal(t, "exec-a", r2.CreateRuleByID("R0001").Name,
		"without a cluster-wide variant, the first stacked variant is the fallback")
}

// Test CreateRulesByID and CreateRulesByName return all variants
func TestRuleStacking_CreateRulesByIDAndName(t *testing.T) {
	r := NewRuleCreator()
	r.SyncRules([]typesv1.Rule{
		rule("", "R0001", "exec", true),
		rule("tenant-a", "R0001", "exec", false),
		rule("tenant-b", "R0001", "exec-alt", false),
	})

	byID := r.CreateRulesByID("R0001")
	assert.Len(t, byID, 3, "CreateRulesByID returns all 3 variants")
	assert.Equal(t, "", byID[0].Bundle)
	assert.Equal(t, "tenant-a", byID[1].Bundle)
	assert.Equal(t, "tenant-b", byID[2].Bundle)

	byName := r.CreateRulesByName("exec")
	assert.Len(t, byName, 2, "CreateRulesByName returns matching variants")
}

// Test GetAllRuleIDs deduplicates IDs across bundles
func TestRuleStacking_GetAllRuleIDsDeduplicated(t *testing.T) {
	r := NewRuleCreator()
	r.SyncRules([]typesv1.Rule{
		rule("", "R0001", "exec", true),
		rule("tenant-a", "R0001", "exec-a", false),
		rule("tenant-b", "R0002", "open-b", false),
	})

	ids := r.GetAllRuleIDs()
	assert.Equal(t, []string{"R0001", "R0002"}, ids, "IDs must be deduplicated")
}

// R-M1: three stacked bundles with the same ID — removal takes the preferred
// (cluster-wide) variant first and leaves the bundle-scoped stack intact.
func TestRuleStacking_MultiStackRemovalOrder(t *testing.T) {
	r := NewRuleCreator()
	r.SyncRules([]typesv1.Rule{
		rule("tenant-a", "R0001", "exec-a", false),
		rule("", "R0001", "exec-clusterwide", true),
		rule("tenant-b", "R0001", "exec-b", false),
	})
	assert.True(t, r.RemoveRuleByID("R0001"))
	assert.Len(t, r.Rules, 2, "removal takes exactly one variant")
	for _, left := range r.Rules {
		assert.False(t, left.ClusterWide, "the cluster-wide variant is removed first")
	}
}

// R-S1: a fragment leaving the cluster removes exactly its rules on the next
// sync; surviving keys keep their (possibly updated) definitions.
func TestRuleStacking_FragmentRemovalDropsItsRules(t *testing.T) {
	r := NewRuleCreator()
	r.SyncRules([]typesv1.Rule{
		rule("base", "R0001", "exec", false),
		rule("overlay", "R0011", "egress", false),
	})
	r.SyncRules([]typesv1.Rule{
		rule("base", "R0001", "exec-updated", false),
	})
	assert.Len(t, r.Rules, 1, "the departed fragment's rules must be gone")
	assert.Equal(t, "exec-updated", r.Rules[0].Name, "the surviving key carries the new definition")
}

// W6: multi-rule fragments with PARTIAL cross-bundle ID overlap — all distinct
// (bundle, ID) keys coexist; evaluation of the overlapping ID prefers the
// cluster-wide (base) variant; removing the base bundle's rules on a re-sync
// leaves the overlay's variant to govern.
func TestRuleStacking_MultiRulePartialOverlapAcrossBundles(t *testing.T) {
	r := NewRuleCreator()
	r.SyncRules([]typesv1.Rule{
		rule("", "R0001", "base-exec", true),
		rule("", "R0004", "base-caps", true),
		rule("", "R0011", "base-egress", true),
		rule("tenant", "R0001", "tenant-exec", false),
		rule("tenant", "R0007", "tenant-open", false),
	})
	assert.Len(t, r.Rules, 5, "partial overlap: every (bundle, ID) key coexists")
	assert.Equal(t, "base-exec", r.CreateRuleByID("R0001").Name, "overlapping ID evaluates to the cluster-wide variant")
	assert.Equal(t, "tenant-open", r.CreateRuleByID("R0007").Name, "overlay-only ID evaluates to the overlay variant")

	// Base bundle departs: overlay's overlapping variant takes over.
	r.SyncRules([]typesv1.Rule{
		rule("tenant", "R0001", "tenant-exec", false),
		rule("tenant", "R0007", "tenant-open", false),
	})
	assert.Len(t, r.Rules, 2)
	assert.Equal(t, "tenant-exec", r.CreateRuleByID("R0001").Name, "after the base departs, the overlay variant governs")
}

// Test UpdateRule with composite keying
func TestRuleStacking_UpdateRuleCompositeKey(t *testing.T) {
	r := NewRuleCreator()
	r.SyncRules([]typesv1.Rule{
		rule("", "R0001", "base-exec", true),
		rule("tenant", "R0001", "tenant-exec", false),
	})

	// Updating cluster-wide rule does not clobber tenant overlay
	updated := r.UpdateRule(rule("", "R0001", "base-exec-updated", true))
	assert.True(t, updated)
	assert.Len(t, r.Rules, 2)

	tenantRule := r.CreateRulesByID("R0001")[1]
	assert.Equal(t, "tenant-exec", tenantRule.Name)

	baseRule := r.CreateRulesByID("R0001")[0]
	assert.Equal(t, "base-exec-updated", baseRule.Name)
}

// Test Concurrent Read/Write safety for lookup methods
func TestRuleStacking_ConcurrentReadWrite(t *testing.T) {
	r := NewRuleCreator()
	r.SyncRules([]typesv1.Rule{
		rule("", "R0001", "base-exec", true),
		rule("tenant", "R0001", "tenant-exec", false),
		rule("tenant", "R0002", "tenant-open", false),
	})

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writer goroutines
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					r.UpdateRule(rule("tenant", "R0001", "tenant-exec-updated", false))
					r.SyncRules([]typesv1.Rule{
						rule("", "R0001", "base-exec", true),
						rule("tenant", "R0001", "tenant-exec", false),
						rule("tenant", "R0002", "tenant-open", false),
					})
				}
			}
		}()
	}

	// Reader goroutines
	var readerWg sync.WaitGroup
	for i := 0; i < 4; i++ {
		readerWg.Add(1)
		go func() {
			defer readerWg.Done()
			for j := 0; j < 200; j++ {
				_ = r.CreateRulesByID("R0001")
				_ = r.CreateRulesByName("base-exec")
				_ = r.CreateRuleByID("R0001")
				_ = r.CreateRuleByName("tenant-exec")
				_ = r.GetAllRuleIDs()
			}
		}()
	}

	readerWg.Wait()
	close(stop)
	wg.Wait()
}
