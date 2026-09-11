package containerprofile

import (
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/kubescape/node-agent/pkg/objectcache"
)

// The kubelet writes projected volumes through an "atomic writer": the real files
// live under a timestamped directory that is replaced wholesale on rotation, and a
// `..data` symlink points at the current one. A ServiceAccount token is therefore
// read at a path like
//
//	/run/secrets/kubernetes.io/serviceaccount/..2026_08_27_14_27_52.163845901/token
//
// The timestamped segment is volatile, so dynamicpathdetector collapses it and the
// learned ContainerProfile records
//
//	/run/secrets/kubernetes.io/serviceaccount/⋯/token
//
// which — because it contains a collapse token — is stored in Opens.Patterns, not
// Opens.Values.
//
// R0006 gates on `!cp.was_path_opened_with_suffix(containerId, '/token')`. With the
// Opens.All branch scanning Values only, a correctly-learned profile answers "no"
// and R0006 fires on every SA-token read for the life of the workload. R0008 has the
// same shape via /proc/⋯/environ.
//
// These tests pin the behaviour the rules actually need. They fail before the
// Patterns scan is added to wasPathOpenedWithSuffix / wasPathOpenedWithPrefix.
// See k8sstormcenter/node-agent#98.

func newPatternProfile(patterns []string, values ...string) *containerProfileLibrary {
	vals := map[string]struct{}{}
	for _, v := range values {
		vals[v] = struct{}{}
	}
	if len(vals) == 0 {
		vals = nil
	}
	pcp := &objectcache.ProjectedContainerProfile{
		Opens: objectcache.ProjectedField{
			All:      true,
			Values:   vals,
			Patterns: patterns,
		},
	}
	return &containerProfileLibrary{objectCache: &mockObjectCacheForPattern{pcp: pcp}}
}

func boolOf(t *testing.T, v interface{ Value() any }) bool {
	t.Helper()
	b, ok := v.Value().(bool)
	if !ok {
		t.Fatalf("expected a bool result, got %T (%v)", v.Value(), v)
	}
	return b
}

// R0006: the profile records the token open as a pattern with a concrete leaf.
func TestSuffix_AtomicWriterServiceAccountToken(t *testing.T) {
	lib := newPatternProfile([]string{
		"/run/secrets/kubernetes.io/serviceaccount/⋯/token",
	})
	if !boolOf(t, lib.wasPathOpenedWithSuffix(types.String("cid"), types.String("/token"))) {
		t.Error("suffix '/token' against recorded pattern " +
			"'/run/secrets/kubernetes.io/serviceaccount/⋯/token': expected true. " +
			"Returning false makes R0006 fire on every SA-token read of a correctly " +
			"learned profile (issue #98)")
	}
}

// R0008: same mechanism, /proc/<pid>/environ.
func TestSuffix_ProcfsEnviron(t *testing.T) {
	lib := newPatternProfile([]string{"/proc/⋯/environ"})
	if !boolOf(t, lib.wasPathOpenedWithSuffix(types.String("cid"), types.String("/environ"))) {
		t.Error("suffix '/environ' against recorded pattern '/proc/⋯/environ': " +
			"expected true (R0008 false-positive otherwise)")
	}
}

// A pattern whose LEAF is itself a wildcard cannot answer a concrete suffix
// question. HasSuffix returns false, which is the same answer as skipping the
// pattern entirely — so scanning Patterns is never worse than not scanning them.
func TestSuffix_WildcardLeafStillUnmatched(t *testing.T) {
	lib := newPatternProfile([]string{"/var/log/pods/⋯"})
	if boolOf(t, lib.wasPathOpenedWithSuffix(types.String("cid"), types.String("/foo.log"))) {
		t.Error("suffix '/foo.log' against wildcard-leaf pattern '/var/log/pods/⋯': " +
			"expected false; the pattern text cannot answer this")
	}
}

// Prefix side: the segments before the first collapse token are concrete, so every
// concrete path the pattern stands for really does start with them.
func TestPrefix_ConcreteHeadOfPattern(t *testing.T) {
	lib := newPatternProfile([]string{"/run/secrets/kubernetes.io/serviceaccount/⋯/token"})
	if !boolOf(t, lib.wasPathOpenedWithPrefix(types.String("cid"),
		types.String("/run/secrets/"))) {
		t.Error("prefix '/run/secrets/' against pattern " +
			"'/run/secrets/kubernetes.io/serviceaccount/⋯/token': expected true; " +
			"the pattern head is concrete")
	}
}

func TestPrefix_UnrelatedHeadStillUnmatched(t *testing.T) {
	lib := newPatternProfile([]string{"/run/secrets/kubernetes.io/serviceaccount/⋯/token"})
	if boolOf(t, lib.wasPathOpenedWithPrefix(types.String("cid"), types.String("/etc/"))) {
		t.Error("prefix '/etc/' against a /run/... pattern: expected false")
	}
}

// Values must keep working, and must still win without consulting Patterns.
func TestSuffix_ConcreteValueStillMatches(t *testing.T) {
	lib := newPatternProfile(nil, "/var/log/concrete.log")
	if !boolOf(t, lib.wasPathOpenedWithSuffix(types.String("cid"), types.String(".log"))) {
		t.Error("suffix '.log' against concrete value '/var/log/concrete.log': expected true")
	}
}

// The two code paths for the same helper must agree. projection_apply.go builds
// SuffixHits with strings.HasSuffix over EVERY raw entry including dynamic ones, so
// a projected profile already answers true for ⋯/token. The Opens.All branch
// answering false for the same profile is the inconsistency issue #98 reports.
func TestSuffix_AllBranchAgreesWithProjectedBranch(t *testing.T) {
	const entry = "/run/secrets/kubernetes.io/serviceaccount/⋯/token"
	const suffix = "/token"

	all := newPatternProfile([]string{entry})
	allAnswer := boolOf(t, all.wasPathOpenedWithSuffix(types.String("cid"), types.String(suffix)))

	// what projection_apply.go would compute for the same raw entry
	projected := &containerProfileLibrary{objectCache: &mockObjectCacheForPattern{
		pcp: &objectcache.ProjectedContainerProfile{
			Opens: objectcache.ProjectedField{
				All:        false,
				SuffixHits: map[string]bool{suffix: true},
			},
		},
	}}
	projectedAnswer := boolOf(t,
		projected.wasPathOpenedWithSuffix(types.String("cid"), types.String(suffix)))

	if allAnswer != projectedAnswer {
		t.Errorf("same profile, two code paths, different answers: "+
			"Opens.All branch=%v, projected branch=%v", allAnswer, projectedAnswer)
	}
}
