//go:build experimental_signing

package cache

import (
	"testing"

	rulemanagertypesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
)

// baseRule is what an admitted base-class fragment produces: cluster-wide, in no
// bundle. It is also what the watcher stamps when rule signing is disabled.
func baseRule(id, name string) rulemanagertypesv1.Rule {
	return rulemanagertypesv1.Rule{ID: id, Name: name, Enabled: true, ClusterWide: true}
}

// overlayRule is what an admitted overlay-class fragment produces: scoped to its
// signed bundle, never cluster-wide.
func overlayRule(id, name, bundleName string) rulemanagertypesv1.Rule {
	return rulemanagertypesv1.Rule{ID: id, Name: name, Enabled: true, Bundle: bundleName}
}

func ids(rules []rulemanagertypesv1.Rule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.ID)
	}
	return out
}

func TestScopeRulesToBundle_BaseRuleAppliesToEveryPod(t *testing.T) {
	in := []rulemanagertypesv1.Rule{baseRule("R0001", "baseline")}

	// Bound to a bundle, bound to another bundle, or bound to none at all.
	for _, b := range []string{"redis", "postgres", ""} {
		got := scopeRulesToBundle(in, b)
		if len(got) != 1 || got[0].Name != "baseline" {
			t.Fatalf("bundle %q: got %+v, want the base rule", b, ids(got))
		}
	}
}

func TestScopeRulesToBundle_OverlayOnlyForItsBundle(t *testing.T) {
	in := []rulemanagertypesv1.Rule{overlayRule("R0002", "redis-only", "redis")}

	if got := scopeRulesToBundle(in, "redis"); len(got) != 1 || got[0].Name != "redis-only" {
		t.Fatalf("in its own bundle: got %+v, want the overlay rule", ids(got))
	}
	if got := scopeRulesToBundle(in, "postgres"); len(got) != 0 {
		t.Fatalf("in another bundle: got %+v, want none", ids(got))
	}
	// A pod with no user-defined-profile label opted into no bundle.
	if got := scopeRulesToBundle(in, ""); len(got) != 0 {
		t.Fatalf("pod with no bundle: got %+v, want none", ids(got))
	}
}

func TestScopeRulesToBundle_OverlayOverridesBaseRule(t *testing.T) {
	in := []rulemanagertypesv1.Rule{
		baseRule("R0001", "cluster-baseline"),
		overlayRule("R0001", "redis-override", "redis"),
		baseRule("R0003", "other"),
	}

	got := scopeRulesToBundle(in, "redis")
	if len(got) != 2 {
		t.Fatalf("in redis: got %+v, want 2 rules", ids(got))
	}
	if got[0].ID != "R0001" || got[0].Name != "redis-override" {
		t.Errorf("in redis: R0001 must be the bundle overlay, got %q", got[0].Name)
	}
	if got[1].ID != "R0003" {
		t.Errorf("in redis: expected R0003 second, got %q", got[1].ID)
	}

	// For another bundle the base rule is untouched and the override invisible.
	got = scopeRulesToBundle(in, "postgres")
	if len(got) != 2 {
		t.Fatalf("in postgres: got %+v, want 2 rules", ids(got))
	}
	if got[0].Name != "cluster-baseline" {
		t.Errorf("in postgres: R0001 must stay the base rule, got %q", got[0].Name)
	}

	// And for a pod bound to no bundle at all.
	got = scopeRulesToBundle(in, "")
	if len(got) != 2 || got[0].Name != "cluster-baseline" {
		t.Errorf("pod with no bundle must get only base rules, got %+v", got)
	}
}

func TestScopeRulesToBundle_OverrideRegardlessOfInputOrder(t *testing.T) {
	// The overlay must win whether it is listed before or after the base rule
	// (the watcher's list order is not stable).
	overlayFirst := []rulemanagertypesv1.Rule{
		overlayRule("R0001", "redis-override", "redis"),
		baseRule("R0001", "cluster-baseline"),
	}
	got := scopeRulesToBundle(overlayFirst, "redis")
	if len(got) != 1 || got[0].Name != "redis-override" {
		t.Fatalf("overlay-first: got %+v", got)
	}
}

func TestScopeRulesToBundle_OverlaysOfOtherBundlesNeverLeak(t *testing.T) {
	// Two vendors ship overlays for R0001. A pod may only ever see its own.
	in := []rulemanagertypesv1.Rule{
		baseRule("R0001", "cluster-baseline"),
		overlayRule("R0001", "redis-override", "redis"),
		overlayRule("R0001", "postgres-override", "postgres"),
	}

	for bundleName, want := range map[string]string{
		"redis":    "redis-override",
		"postgres": "postgres-override",
		"nginx":    "cluster-baseline",
		"":         "cluster-baseline",
	} {
		got := scopeRulesToBundle(in, bundleName)
		if len(got) != 1 {
			t.Fatalf("bundle %q: got %+v, want exactly one R0001", bundleName, got)
		}
		if got[0].Name != want {
			t.Errorf("bundle %q: R0001 = %q, want %q", bundleName, got[0].Name, want)
		}
	}
}

func TestScopeRulesToBundle_BundleIsNamespaceIndependent(t *testing.T) {
	// The whole point of scoping by bundle: the same signed overlay applies to
	// every workload that opted in, no matter which namespace it runs in. The
	// input carries no namespace at all any more, so this is really an assertion
	// that scoping depends on nothing but the bundle string.
	in := []rulemanagertypesv1.Rule{
		baseRule("R0001", "cluster-baseline"),
		overlayRule("R0001", "redis-override", "redis"),
	}
	first := scopeRulesToBundle(in, "redis")
	second := scopeRulesToBundle(in, "redis")
	if len(first) != 1 || first[0].Name != "redis-override" {
		t.Fatalf("got %+v", first)
	}
	if len(second) != len(first) || second[0].Name != first[0].Name {
		t.Fatalf("scoping is not deterministic: %+v vs %+v", first, second)
	}
}

func TestScopeRulesToBundle_NoProvenanceUnchanged(t *testing.T) {
	// Rule signing disabled: the watcher stamps ClusterWide=true and an empty
	// Bundle, so scoping is an exact pass-through for every pod — including
	// duplicate IDs contributed by two rule bindings with different prefilter
	// parameters, which must NOT be collapsed.
	in := []rulemanagertypesv1.Rule{
		baseRule("R0001", "a"),
		baseRule("R0002", "b"),
		baseRule("R0001", "a-with-other-params"),
		baseRule("R0003", "c"),
	}
	for _, b := range []string{"anything", ""} {
		got := scopeRulesToBundle(in, b)
		if len(got) != len(in) {
			t.Fatalf("bundle %q: got %+v, want all %d rules unchanged", b, ids(got), len(in))
		}
		for i := range in {
			if got[i].ID != in[i].ID || got[i].Name != in[i].Name {
				t.Fatalf("input was altered at %d: %+v vs %+v", i, got[i], in[i])
			}
		}
	}
}

// Rules registered directly by a third party carry no provenance at all: not
// ClusterWide, not bundled. They predate rule signing and must go through the
// same untouched fast path, duplicates included.
func TestScopeRulesToBundle_UnstampedRulesUnchanged(t *testing.T) {
	in := []rulemanagertypesv1.Rule{
		{ID: "R0001", Name: "a", Enabled: true},
		{ID: "R0001", Name: "a-with-other-params", Enabled: true},
		{ID: "R0002", Name: "b", Enabled: true},
	}
	for _, b := range []string{"redis", ""} {
		got := scopeRulesToBundle(in, b)
		if len(got) != len(in) {
			t.Fatalf("bundle %q: got %+v, want all %d rules unchanged", b, ids(got), len(in))
		}
		for i := range in {
			if got[i].Name != in[i].Name {
				t.Fatalf("input was altered at %d: %+v vs %+v", i, got[i], in[i])
			}
		}
	}
}

// A rule registered directly by a third party carries no provenance at all
// (neither ClusterWide nor a Bundle). It must be treated as cluster-wide, never
// silently dropped.
func TestScopeRulesToBundle_UnstampedRuleTreatedAsClusterWide(t *testing.T) {
	in := []rulemanagertypesv1.Rule{
		{ID: "R0009", Name: "third-party", Enabled: true},
		overlayRule("R0001", "redis-override", "redis"),
	}
	got := scopeRulesToBundle(in, "redis")
	if len(got) != 2 {
		t.Fatalf("got %+v, want both rules", ids(got))
	}
	if got := scopeRulesToBundle(in, "postgres"); len(got) != 1 || got[0].ID != "R0009" {
		t.Fatalf("got %+v, want only the unstamped rule", ids(got))
	}
}

func TestScopeRulesToBundle_Empty(t *testing.T) {
	if got := scopeRulesToBundle(nil, "redis"); len(got) != 0 {
		t.Fatalf("got %+v, want none", got)
	}
}
