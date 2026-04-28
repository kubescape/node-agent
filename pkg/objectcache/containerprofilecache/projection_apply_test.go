package containerprofilecache

import (
	"testing"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// --- helpers ---

func allSpec() objectcache.FieldSpec {
	return objectcache.FieldSpec{InUse: true, All: true}
}

func exactSpec(paths ...string) objectcache.FieldSpec {
	m := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		m[p] = struct{}{}
	}
	return objectcache.FieldSpec{InUse: true, Exact: m}
}

func prefixSpecBuilt(prefixes ...string) objectcache.FieldSpec {
	f := objectcache.FieldSpec{
		InUse:    true,
		Prefixes: prefixes,
	}
	f.PrefixMatcher = newTrie(prefixes)
	return f
}

func suffixSpecBuilt(suffixes ...string) objectcache.FieldSpec {
	f := objectcache.FieldSpec{
		InUse:    true,
		Suffixes: suffixes,
	}
	f.SuffixMatcher = &suffixTrieMatcher{t: newSuffixTrie(suffixes)}
	return f
}

func emptyCP() *v1beta1.ContainerProfile {
	return &v1beta1.ContainerProfile{}
}

// --- tests ---

// TestApply_NilCP verifies that Apply with a nil ContainerProfile returns a
// non-nil ProjectedContainerProfile with no data.
func TestApply_NilCP(t *testing.T) {
	spec := &objectcache.RuleProjectionSpec{Hash: "h1"}
	pcp := Apply(spec, nil, nil)

	require.NotNil(t, pcp)
	assert.Equal(t, "h1", pcp.SpecHash)
	assert.Nil(t, pcp.Opens.Values)
	assert.Nil(t, pcp.Execs.Values)
}

// TestApply_NilSpec verifies that Apply with a nil spec returns a non-nil
// ProjectedContainerProfile with an empty SpecHash and no projected data.
func TestApply_NilSpec(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		Spec: v1beta1.ContainerProfileSpec{
			Capabilities: []string{"SYS_PTRACE"},
		},
	}
	pcp := Apply(nil, cp, nil)

	require.NotNil(t, pcp)
	assert.Empty(t, pcp.SpecHash)
	// No field should have data because spec is nil → zero spec → InUse=false everywhere.
	assert.Nil(t, pcp.Capabilities.Values)
	assert.False(t, pcp.Capabilities.All)
}

// TestApply_AllSurfaces verifies that when all surfaces have All=true, the
// projected profile contains all data from the ContainerProfile.
func TestApply_AllSurfaces(t *testing.T) {
	spec := &objectcache.RuleProjectionSpec{
		Opens:           allSpec(),
		Execs:           allSpec(),
		Capabilities:    allSpec(),
		Syscalls:        allSpec(),
		EgressDomains:   allSpec(),
		EgressAddresses: allSpec(),
	}
	cp := &v1beta1.ContainerProfile{
		Spec: v1beta1.ContainerProfileSpec{
			Opens:        []v1beta1.OpenCalls{{Path: "/etc/passwd", Flags: []string{"O_RDONLY"}}},
			Execs:        []v1beta1.ExecCalls{{Path: "/bin/ls", Args: []string{"-la"}}},
			Capabilities: []string{"NET_ADMIN"},
			Syscalls:     []string{"read", "write"},
			Egress: []v1beta1.NetworkNeighbor{
				{DNS: "example.com", IPAddress: "1.2.3.4"},
			},
		},
	}

	pcp := Apply(spec, cp, nil)
	require.NotNil(t, pcp)

	assert.True(t, pcp.Opens.All)
	_, hasPasswd := pcp.Opens.Values["/etc/passwd"]
	assert.True(t, hasPasswd, "Opens.Values should contain /etc/passwd")

	assert.True(t, pcp.Execs.All)
	_, hasLs := pcp.Execs.Values["/bin/ls"]
	assert.True(t, hasLs, "Execs.Values should contain /bin/ls")

	assert.True(t, pcp.Capabilities.All)
	_, hasNetAdmin := pcp.Capabilities.Values["NET_ADMIN"]
	assert.True(t, hasNetAdmin, "Capabilities.Values should contain NET_ADMIN")

	assert.True(t, pcp.Syscalls.All)
	_, hasRead := pcp.Syscalls.Values["read"]
	assert.True(t, hasRead, "Syscalls.Values should contain read")
}

// TestApply_ExactFilter verifies that only the exact-matched path is retained.
func TestApply_ExactFilter(t *testing.T) {
	spec := &objectcache.RuleProjectionSpec{
		Opens: exactSpec("/bin/sh"),
	}
	cp := &v1beta1.ContainerProfile{
		Spec: v1beta1.ContainerProfileSpec{
			Opens: []v1beta1.OpenCalls{
				{Path: "/bin/sh", Flags: []string{"O_RDONLY"}},
				{Path: "/etc/passwd", Flags: []string{"O_RDONLY"}},
			},
		},
	}

	pcp := Apply(spec, cp, nil)
	require.NotNil(t, pcp)

	_, hasSh := pcp.Opens.Values["/bin/sh"]
	assert.True(t, hasSh, "Opens.Values should contain /bin/sh")
	_, hasPasswd := pcp.Opens.Values["/etc/passwd"]
	assert.False(t, hasPasswd, "Opens.Values should NOT contain /etc/passwd")
}

// TestApply_PrefixFilter verifies that only paths matching the prefix are retained.
func TestApply_PrefixFilter(t *testing.T) {
	spec := &objectcache.RuleProjectionSpec{
		Opens: prefixSpecBuilt("/bin/"),
	}
	cp := &v1beta1.ContainerProfile{
		Spec: v1beta1.ContainerProfileSpec{
			Opens: []v1beta1.OpenCalls{
				{Path: "/bin/sh"},
				{Path: "/bin/bash"},
				{Path: "/etc/passwd"},
			},
		},
	}

	pcp := Apply(spec, cp, nil)
	require.NotNil(t, pcp)

	_, hasSh := pcp.Opens.Values["/bin/sh"]
	assert.True(t, hasSh, "/bin/sh should be retained by /bin/ prefix")
	_, hasBash := pcp.Opens.Values["/bin/bash"]
	assert.True(t, hasBash, "/bin/bash should be retained by /bin/ prefix")
	_, hasPasswd := pcp.Opens.Values["/etc/passwd"]
	assert.False(t, hasPasswd, "/etc/passwd should be filtered out")
}

// TestApply_SuffixFilter verifies that only paths matching the suffix are retained.
func TestApply_SuffixFilter(t *testing.T) {
	spec := &objectcache.RuleProjectionSpec{
		Opens: suffixSpecBuilt(".conf"),
	}
	cp := &v1beta1.ContainerProfile{
		Spec: v1beta1.ContainerProfileSpec{
			Opens: []v1beta1.OpenCalls{
				{Path: "/etc/app.conf"},
				{Path: "/etc/passwd"},
			},
		},
	}

	pcp := Apply(spec, cp, nil)
	require.NotNil(t, pcp)

	_, hasConf := pcp.Opens.Values["/etc/app.conf"]
	assert.True(t, hasConf, "/etc/app.conf should be retained by .conf suffix")
	_, hasPasswd := pcp.Opens.Values["/etc/passwd"]
	assert.False(t, hasPasswd, "/etc/passwd should be filtered out")
}

// TestApply_DynamicRetentionWhenInUse verifies that paths containing
// dynamicpathdetector.DynamicIdentifier go to Patterns (not Values) when the
// surface is InUse.
func TestApply_DynamicRetentionWhenInUse(t *testing.T) {
	dynamicPath := "/data/" + dynamicpathdetector.DynamicIdentifier + "/config"
	spec := &objectcache.RuleProjectionSpec{
		Opens: allSpec(),
	}
	cp := &v1beta1.ContainerProfile{
		Spec: v1beta1.ContainerProfileSpec{
			Opens: []v1beta1.OpenCalls{
				{Path: dynamicPath},
				{Path: "/etc/passwd"},
			},
		},
	}

	pcp := Apply(spec, cp, nil)
	require.NotNil(t, pcp)

	assert.Contains(t, pcp.Opens.Patterns, dynamicPath, "dynamic path should go to Patterns")
	_, inValues := pcp.Opens.Values[dynamicPath]
	assert.False(t, inValues, "dynamic path should NOT be in Values")
	_, hasPasswd := pcp.Opens.Values["/etc/passwd"]
	assert.True(t, hasPasswd, "/etc/passwd should still be in Values")
}

// TestApply_DynamicNotRetainedWhenNotInUse verifies that when InUse=false,
// dynamic paths are not included in anything.
func TestApply_DynamicNotRetainedWhenNotInUse(t *testing.T) {
	dynamicPath := "/proc/" + dynamicpathdetector.DynamicIdentifier + "/maps"
	spec := &objectcache.RuleProjectionSpec{
		// Opens.InUse is false (zero value)
	}
	cp := &v1beta1.ContainerProfile{
		Spec: v1beta1.ContainerProfileSpec{
			Opens: []v1beta1.OpenCalls{
				{Path: dynamicPath},
			},
		},
	}

	pcp := Apply(spec, cp, nil)
	require.NotNil(t, pcp)

	assert.Empty(t, pcp.Opens.Patterns, "dynamic path should NOT be in Patterns when InUse=false")
	assert.Nil(t, pcp.Opens.Values, "Values should be nil when InUse=false")
}

// TestApply_PrefixHitsCoverAllDeclared verifies that PrefixHits is populated
// for all declared prefixes, with true only for those with a matching entry.
func TestApply_PrefixHitsCoverAllDeclared(t *testing.T) {
	spec := &objectcache.RuleProjectionSpec{
		Opens: prefixSpecBuilt("/bin/", "/usr/"),
	}
	cp := &v1beta1.ContainerProfile{
		Spec: v1beta1.ContainerProfileSpec{
			Opens: []v1beta1.OpenCalls{
				{Path: "/bin/sh"},
				{Path: "/etc/passwd"},
			},
		},
	}

	pcp := Apply(spec, cp, nil)
	require.NotNil(t, pcp)

	hitBin, okBin := pcp.Opens.PrefixHits["/bin/"]
	require.True(t, okBin, "/bin/ should be in PrefixHits")
	assert.True(t, hitBin, "/bin/ should have a hit")

	hitUsr, okUsr := pcp.Opens.PrefixHits["/usr/"]
	require.True(t, okUsr, "/usr/ should be in PrefixHits")
	assert.False(t, hitUsr, "/usr/ should NOT have a hit (no entries)")
}

// TestApply_PatternsDedupedAndSorted verifies that identical dynamic entries
// appear only once in Patterns, and Patterns is sorted.
func TestApply_PatternsDedupedAndSorted(t *testing.T) {
	dynamicPath := "/data/" + dynamicpathdetector.DynamicIdentifier + "/file"
	spec := &objectcache.RuleProjectionSpec{
		Opens: allSpec(),
	}
	cp := &v1beta1.ContainerProfile{
		Spec: v1beta1.ContainerProfileSpec{
			Opens: []v1beta1.OpenCalls{
				{Path: dynamicPath},
				{Path: dynamicPath},
				{Path: dynamicPath},
			},
		},
	}

	pcp := Apply(spec, cp, nil)
	require.NotNil(t, pcp)

	assert.Equal(t, 1, len(pcp.Opens.Patterns), "duplicate dynamic paths should be deduped to one entry")
	assert.Equal(t, dynamicPath, pcp.Opens.Patterns[0])
}

// TestApply_Idempotent verifies that calling Apply twice on the same inputs
// produces equal results.
func TestApply_Idempotent(t *testing.T) {
	spec := &objectcache.RuleProjectionSpec{
		Opens: prefixSpecBuilt("/bin/"),
		Execs: allSpec(),
	}
	cp := &v1beta1.ContainerProfile{
		Spec: v1beta1.ContainerProfileSpec{
			Opens: []v1beta1.OpenCalls{
				{Path: "/bin/sh", Flags: []string{"O_RDONLY"}},
			},
			Execs: []v1beta1.ExecCalls{
				{Path: "/usr/bin/curl", Args: []string{"--help"}},
			},
		},
	}

	pcp1 := Apply(spec, cp, nil)
	pcp2 := Apply(spec, cp, nil)

	assert.Equal(t, pcp1.SpecHash, pcp2.SpecHash)
	assert.Equal(t, pcp1.Opens.Values, pcp2.Opens.Values)
	assert.Equal(t, pcp1.Opens.Patterns, pcp2.Opens.Patterns)
	assert.Equal(t, pcp1.Execs.Values, pcp2.Execs.Values)
}

// TestApply_SyncChecksum verifies that the SyncChecksum annotation value is
// copied to pcp.SyncChecksum.
func TestApply_SyncChecksum(t *testing.T) {
	spec := &objectcache.RuleProjectionSpec{}
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				helpersv1.SyncChecksumMetadataKey: "abc123",
			},
		},
	}

	pcp := Apply(spec, cp, nil)
	require.NotNil(t, pcp)
	assert.Equal(t, "abc123", pcp.SyncChecksum)
}

// TestApply_SyncChecksum_MissingAnnotation verifies that when the annotation is
// absent, SyncChecksum is empty (not panics or errors).
func TestApply_SyncChecksum_MissingAnnotation(t *testing.T) {
	spec := &objectcache.RuleProjectionSpec{}
	cp := emptyCP()

	pcp := Apply(spec, cp, nil)
	require.NotNil(t, pcp)
	assert.Empty(t, pcp.SyncChecksum)
}

// TestApply_SpecHashInResult verifies that the spec's Hash value is copied to
// pcp.SpecHash.
func TestApply_SpecHashInResult(t *testing.T) {
	spec := &objectcache.RuleProjectionSpec{Hash: "myhash"}
	pcp := Apply(spec, emptyCP(), nil)

	require.NotNil(t, pcp)
	assert.Equal(t, "myhash", pcp.SpecHash)
}

// TestApply_PolicyByRuleIdCopied verifies that PolicyByRuleId is shallow-copied
// from the ContainerProfile to the ProjectedContainerProfile.
func TestApply_PolicyByRuleIdCopied(t *testing.T) {
	spec := &objectcache.RuleProjectionSpec{}
	policy := v1beta1.RulePolicy{AllowedProcesses: []string{"ls", "cat"}}
	cp := &v1beta1.ContainerProfile{
		Spec: v1beta1.ContainerProfileSpec{
			PolicyByRuleId: map[string]v1beta1.RulePolicy{
				"R0001": policy,
				"R0002": {AllowedContainer: true},
			},
		},
	}

	pcp := Apply(spec, cp, nil)
	require.NotNil(t, pcp)
	require.Len(t, pcp.PolicyByRuleId, 2, "all PolicyByRuleId entries should be copied")
	assert.Equal(t, policy, pcp.PolicyByRuleId["R0001"])
	assert.True(t, pcp.PolicyByRuleId["R0002"].AllowedContainer)
}

// TestApply_PolicyByRuleId_Empty verifies that when PolicyByRuleId is empty, the
// projected map is nil (not an allocated empty map).
func TestApply_PolicyByRuleId_Empty(t *testing.T) {
	spec := &objectcache.RuleProjectionSpec{}
	cp := emptyCP()

	pcp := Apply(spec, cp, nil)
	require.NotNil(t, pcp)
	assert.Nil(t, pcp.PolicyByRuleId, "empty PolicyByRuleId should result in nil map")
}

// TestApply_ExactFilter_NoMatchYieldsNilValues verifies that when no open entry
// matches the exact filter, Values is nil (not an empty non-nil map).
func TestApply_ExactFilter_NoMatchYieldsNilValues(t *testing.T) {
	spec := &objectcache.RuleProjectionSpec{
		Opens: exactSpec("/nonexistent"),
	}
	cp := &v1beta1.ContainerProfile{
		Spec: v1beta1.ContainerProfileSpec{
			Opens: []v1beta1.OpenCalls{
				{Path: "/etc/passwd"},
			},
		},
	}

	pcp := Apply(spec, cp, nil)
	require.NotNil(t, pcp)
	assert.Nil(t, pcp.Opens.Values, "Values should be nil when no entries match the filter")
}
