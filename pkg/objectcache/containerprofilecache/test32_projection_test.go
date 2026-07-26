package containerprofilecache

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/objectcache/callstackcache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestT32_UserOverlayExecsReachProjectedValues pins the contract that
// Test_32_UnexpectedProcessArguments depends on end-to-end: when a user-
// defined ApplicationProfile overlay supplies Execs entries for a
// container, those paths MUST appear in the projected ContainerProfile's
// Execs.Values so ap.was_executed lookups succeed and R0001 stays
// silent on user-allowed paths.
//
// Test_32 has been failing on the R0001-silence precondition even after
// the bare-name path enumeration in the test's profile. That can only
// happen if one of these projection steps drops the entries:
//
//  1. projectUserProfiles → mergeApplicationProfile fails to copy
//     userAP.Spec.Containers[i].Execs into projected.Spec.Execs
//  2. Apply → extractExecsPaths walks projected.Spec.Execs[i].Path but
//     misses entries
//  3. projectField → entries end up in Patterns or get filtered out
//     instead of landing in Values
//
// This test stresses (1)+(2)+(3) end-to-end with an empty baseline
// (mirrors the real Test_32 scenario where the agent's recording side
// correctly skips learning for user-defined-profile containers).
func TestT32_UserOverlayExecsReachProjectedValues(t *testing.T) {
	// Empty baseline ContainerProfile (matches what the reconciler
	// synthesises when no baseline exists for a user-defined-profile-
	// labelled container).
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "replicaset-curl-32-6d44f5f86b",
			Namespace: "ns",
		},
	}

	// User-defined AP with the same Execs shape Test_32 uses
	// (post-c3b692ed, both full-path and bare-name variants).
	userAP := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "curl-32-overlay", Namespace: "ns"},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{
				{
					Name: "curl",
					Execs: []v1beta1.ExecCalls{
						{Path: "/bin/sh", Args: []string{"sh", "-c", "*"}},
						{Path: "sh", Args: []string{"sh", "-c", "*"}},
						{Path: "/bin/echo", Args: []string{"echo", "hello", "*"}},
					},
				},
			},
		},
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "curl"}},
		},
	}

	merged, _ := projectUserProfiles(cp, userAP, nil, pod, "curl")
	if merged == nil {
		t.Fatalf("projectUserProfiles returned nil")
	}

	// After merge, projected.Spec.Execs must contain all 3 user-overlay
	// Execs paths.
	gotPaths := map[string]bool{}
	for _, e := range merged.Spec.Execs {
		gotPaths[e.Path] = true
	}
	wantPaths := []string{"/bin/sh", "sh", "/bin/echo"}
	for _, p := range wantPaths {
		if !gotPaths[p] {
			t.Errorf("merge failed: path %q missing from merged.Spec.Execs (got: %v)", p, gotPaths)
		}
	}

	// Apply with a default RuleProjectionSpec (InUse=false → All=true →
	// pass-through; matches what R0001 hits when no rule declares a
	// specific Execs requirement).
	spec := &objectcache.RuleProjectionSpec{}
	tree := callstackcache.NewCallStackSearchTree()
	projected := Apply(spec, merged, tree)

	if projected == nil {
		t.Fatal("Apply returned nil")
	}
	if projected.Execs.Values == nil {
		t.Fatalf("projected.Execs.Values is nil — projection dropped all entries")
	}
	for _, p := range wantPaths {
		if _, ok := projected.Execs.Values[p]; !ok {
			t.Errorf("projection dropped %q: projected.Execs.Values=%v", p, projected.Execs.Values)
		}
	}

	// ExecsByPath is the path → args map used by R0040's
	// was_executed_with_args. Must also carry all 3 user paths.
	for _, p := range wantPaths {
		if _, ok := projected.ExecsByPath[p]; !ok {
			t.Errorf("ExecsByPath missing path %q (got keys: %v)", p, mapKeys(projected.ExecsByPath))
		}
	}
}

// TestT32_StampOverlayIdentity_Idempotent pins the contract behind the
// CodeRabbit critical finding on projection.go:115 (PR #43): stamping
// the same overlay identity twice MUST produce the same SyncChecksum
// as stamping it once. Both reconciler.go and tryPopulateEntry path
// through projectUserProfiles, and a reconciler tick that re-stamps
// an already-stamped projected ContainerProfile must NOT accumulate
// overlay suffixes.
//
// Bug shape (pre-fix): stampOverlayIdentity reads the existing
// SyncChecksumMetadataKey annotation as "baseline" and appends new
// overlay suffixes to it. On the second call, the first call's
// "ap=ns/name@RV" segment is treated as part of the "baseline" and
// gets a second "ap=ns/name@RV" appended. Result:
//
//   baseline:                              ""
//   first stamp:    "|ap=ns/curl@1"
//   second stamp:   "|ap=ns/curl@1|ap=ns/curl@1"   ← BUG: duplicated
//
// The cache key keeps changing across reconciler ticks even though
// the overlay didn't change — invalidates the function_cache on every
// tick, churning expensive recomputations.
func TestT32_StampOverlayIdentity_Idempotent(t *testing.T) {
	userAP := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "curl-32-overlay",
			Namespace:       "ns",
			ResourceVersion: "42",
		},
	}

	// Stamp once on a fresh cp; capture the checksum.
	cp1 := &v1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Name: "cp"}}
	stampOverlayIdentity(cp1, userAP, nil)
	once := cp1.Annotations["kubescape.io/sync-checksum"]

	// Stamp twice on a different fresh cp (simulates reconciler tick
	// re-projecting an already-projected entry).
	cp2 := &v1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Name: "cp"}}
	stampOverlayIdentity(cp2, userAP, nil)
	stampOverlayIdentity(cp2, userAP, nil)
	twice := cp2.Annotations["kubescape.io/sync-checksum"]

	if once != twice {
		t.Errorf("stampOverlayIdentity not idempotent on repeat-stamp:\n  once:  %q\n  twice: %q\n"+
			"overlay suffixes accumulate, churning the function_cache on every reconcile.", once, twice)
	}

	// Three times must also equal once.
	cp3 := &v1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Name: "cp"}}
	stampOverlayIdentity(cp3, userAP, nil)
	stampOverlayIdentity(cp3, userAP, nil)
	stampOverlayIdentity(cp3, userAP, nil)
	if got := cp3.Annotations["kubescape.io/sync-checksum"]; got != once {
		t.Errorf("triple-stamp also non-idempotent: got %q want %q", got, once)
	}
}

// TestT32_StampOverlayIdentity_PreservesBaseline pins that a non-empty
// baseline SyncChecksum survives the stamp (we don't blow away the
// learned profile's content hash; we extend it). Distinct baselines
// must produce distinct keys after stamping.
func TestT32_StampOverlayIdentity_PreservesBaseline(t *testing.T) {
	userAP := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "ovrl", Namespace: "ns", ResourceVersion: "1"},
	}

	cpA := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "cp",
			Annotations: map[string]string{"kubescape.io/sync-checksum": "baseline-A"},
		},
	}
	stampOverlayIdentity(cpA, userAP, nil)

	cpB := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "cp",
			Annotations: map[string]string{"kubescape.io/sync-checksum": "baseline-B"},
		},
	}
	stampOverlayIdentity(cpB, userAP, nil)

	if cpA.Annotations["kubescape.io/sync-checksum"] == cpB.Annotations["kubescape.io/sync-checksum"] {
		t.Errorf("distinct baselines produced same stamped checksum — baseline lost during stamp")
	}
}

// TestT32_SyncChecksumReflectsUserOverlayIdentity pins the contract
// that the cache-invalidation key (ProjectedContainerProfile.SyncChecksum)
// CHANGES when a user-overlay AP is added to a previously empty
// baseline. Without this, the rulemanager's function_cache caches an
// "was_executed=false" result computed BEFORE the overlay merged and
// returns it forever — the bug behind Test_32's persistent failure
// where user-overlay /bin/sh in profile.Spec.Execs never reaches the
// rule evaluator's cached lookup result.
//
// HashForContainerProfile in pkg/rulemanager/cel/libraries/cache/
// function_cache.go:105 builds the cache key as
// SpecHash + "|" + SyncChecksum. SpecHash only tracks rule changes.
// SyncChecksum is the ONLY field that's supposed to flip when the
// underlying profile content changes.
//
// Failure mode: empty baseline + first projection (no overlay yet,
// transient fetch error) → SyncChecksum=""; rule caches result;
// reconciler later succeeds the overlay fetch and re-projects → still
// SyncChecksum="" because cp.Annotations[SyncChecksumMetadataKey]
// only reflects the BASELINE, not the merged user-overlay identity.
func TestT32_SyncChecksumReflectsUserOverlayIdentity(t *testing.T) {
	// Empty baseline (matches reconciler's synthesised effectiveCP for
	// a user-defined-profile-labelled container).
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "replicaset-curl-32-6d44f5f86b",
			Namespace: "ns",
			// Reconciler-synthesised baselines do NOT carry a
			// SyncChecksumMetadataKey annotation. The bug is that the
			// projected SyncChecksum stays "" across both states.
		},
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "curl"}},
		},
	}

	spec := &objectcache.RuleProjectionSpec{}
	tree := callstackcache.NewCallStackSearchTree()

	// Stage 1: project WITHOUT user-overlay (first-pass under transient
	// fetch failure). Compute SyncChecksum_before.
	mergedNoOverlay, _ := projectUserProfiles(cp, nil, nil, pod, "curl")
	projectedNoOverlay := Apply(spec, mergedNoOverlay, tree)
	syncBefore := projectedNoOverlay.SyncChecksum

	// Stage 2: project WITH a user-overlay AP. Same baseline, same
	// container. SyncChecksum_after MUST differ from SyncChecksum_before.
	userAP := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "curl-32-overlay",
			Namespace:       "ns",
			ResourceVersion: "12345",
		},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{
				{
					Name:  "curl",
					Execs: []v1beta1.ExecCalls{{Path: "/bin/sh", Args: []string{"sh", "-c", "*"}}},
				},
			},
		},
	}
	mergedWithOverlay, _ := projectUserProfiles(cp, userAP, nil, pod, "curl")
	projectedWithOverlay := Apply(spec, mergedWithOverlay, tree)
	syncAfter := projectedWithOverlay.SyncChecksum

	if syncBefore == syncAfter {
		t.Errorf("SyncChecksum did not change after user-overlay merge: before=%q after=%q. "+
			"The function_cache key won't invalidate when the overlay arrives, so "+
			"stale was_executed=false results poison the rule evaluator indefinitely. "+
			"Apply (projection_apply.go) must fold user-overlay identity (e.g. userAP.ResourceVersion) "+
			"into projected.SyncChecksum.",
			syncBefore, syncAfter)
	}

	// Stage 3: project with a DIFFERENT user-overlay AP (e.g., the
	// overlay was updated post-deployment). SyncChecksum_third MUST
	// differ from syncAfter so the cache picks up the change.
	userAPUpdated := userAP.DeepCopy()
	userAPUpdated.ResourceVersion = "12346"
	userAPUpdated.Spec.Containers[0].Execs = append(userAPUpdated.Spec.Containers[0].Execs,
		v1beta1.ExecCalls{Path: "/bin/echo", Args: []string{"echo", "*"}})
	mergedWithUpdated, _ := projectUserProfiles(cp, userAPUpdated, nil, pod, "curl")
	projectedWithUpdated := Apply(spec, mergedWithUpdated, tree)
	syncThird := projectedWithUpdated.SyncChecksum

	if syncAfter == syncThird {
		t.Errorf("SyncChecksum did not change after user-overlay update (RV %s → %s, +1 Exec entry): "+
			"before-update=%q after-update=%q. Updates to the overlay won't invalidate cached lookups.",
			userAP.ResourceVersion, userAPUpdated.ResourceVersion, syncAfter, syncThird)
	}

	// Stage 4: project AGAIN without an overlay (simulates the overlay
	// label being removed from the pod, or the overlay AP being deleted
	// from storage). SyncChecksum MUST fall back to a value DISTINCT
	// from the overlay-stamped one, so the function_cache invalidates
	// when the overlay disappears. CodeRabbit PR #43 nitpick on
	// test32_projection_test.go:210.
	mergedRemoved, _ := projectUserProfiles(cp, nil, nil, pod, "curl")
	projectedRemoved := Apply(spec, mergedRemoved, tree)
	syncRemoved := projectedRemoved.SyncChecksum

	if syncRemoved == syncThird {
		t.Errorf("SyncChecksum did not change after user-overlay REMOVAL: "+
			"with-overlay=%q without-overlay=%q. Removing the overlay won't invalidate cached lookups.",
			syncThird, syncRemoved)
	}
	if syncRemoved != syncBefore {
		t.Errorf("after overlay removal, SyncChecksum should match the baseline-only state: "+
			"removed=%q baseline-only=%q", syncRemoved, syncBefore)
	}
}

func mapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
