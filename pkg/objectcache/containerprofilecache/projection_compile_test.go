package containerprofilecache

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/objectcache"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeRule is a helper that builds a Rule with a ProfileDataRequired.
func makeRule(pdr *typesv1.ProfileDataRequired) typesv1.Rule {
	return typesv1.Rule{
		ID:                  "test-rule",
		ProfileDataRequired: pdr,
	}
}

// fieldReqAll returns a FieldRequirement that requests all entries.
func fieldReqAll() typesv1.FieldRequirement {
	return typesv1.FieldRequirement{Declared: true, All: true}
}

// fieldReqPatterns returns a FieldRequirement with the supplied patterns.
func fieldReqPatterns(patterns ...typesv1.PatternObject) typesv1.FieldRequirement {
	return typesv1.FieldRequirement{Declared: true, Patterns: patterns}
}

func exactPattern(path string) typesv1.PatternObject {
	return typesv1.PatternObject{Exact: path}
}

func prefixPattern(path string) typesv1.PatternObject {
	return typesv1.PatternObject{Prefix: path}
}

func suffixPattern(path string) typesv1.PatternObject {
	return typesv1.PatternObject{Suffix: path}
}

func containsPattern(s string) typesv1.PatternObject {
	return typesv1.PatternObject{Contains: s}
}

// TestCompileSpec_Empty verifies that an empty rule list produces a spec where
// all FieldSpec.InUse fields are false.
func TestCompileSpec_Empty(t *testing.T) {
	spec := CompileSpec(nil)

	fields := []objectcache.FieldSpec{
		spec.Opens, spec.Execs, spec.Capabilities, spec.Syscalls,
		spec.Endpoints, spec.EgressDomains, spec.EgressAddresses,
		spec.IngressDomains, spec.IngressAddresses,
	}
	for i, f := range fields {
		assert.False(t, f.InUse, "field %d should not be in use when no rules provided", i)
		assert.False(t, f.All, "field %d All should be false when no rules provided", i)
	}
}

// TestCompileSpec_NilProfileDataRequiredSkipped verifies that rules with nil
// ProfileDataRequired do not contribute to the spec.
func TestCompileSpec_NilProfileDataRequiredSkipped(t *testing.T) {
	rules := []typesv1.Rule{
		{ID: "no-pdr", ProfileDataRequired: nil},
		{ID: "also-no-pdr", ProfileDataRequired: nil},
	}
	spec := CompileSpec(rules)

	assert.False(t, spec.Opens.InUse, "opens should not be in use when all rules have nil ProfileDataRequired")
	assert.False(t, spec.Execs.InUse, "execs should not be in use when all rules have nil ProfileDataRequired")
}

// TestCompileSpec_DeterministicHash verifies that the same rules compiled twice
// produce the same hash, and that rule ordering does not change the hash.
func TestCompileSpec_DeterministicHash(t *testing.T) {
	pdr := &typesv1.ProfileDataRequired{
		Opens: fieldReqPatterns(exactPattern("/bin/sh"), prefixPattern("/usr/")),
		Execs: fieldReqAll(),
	}
	rule := makeRule(pdr)

	spec1 := CompileSpec([]typesv1.Rule{rule})
	spec2 := CompileSpec([]typesv1.Rule{rule})
	assert.Equal(t, spec1.Hash, spec2.Hash, "same rules should always produce the same hash")
	assert.NotEmpty(t, spec1.Hash, "hash should not be empty")

	// Order of rules should not change the hash.
	pdr2 := &typesv1.ProfileDataRequired{
		Execs: fieldReqAll(),
	}
	rule2 := typesv1.Rule{ID: "r2", ProfileDataRequired: pdr2}

	specAB := CompileSpec([]typesv1.Rule{rule, rule2})
	specBA := CompileSpec([]typesv1.Rule{rule2, rule})
	assert.Equal(t, specAB.Hash, specBA.Hash, "rule order should not affect hash")
}

// TestCompileSpec_AllPoisonsField verifies that a single rule with Opens.All=true
// makes spec.Opens.All=true regardless of other rules with exact patterns.
func TestCompileSpec_AllPoisonsField(t *testing.T) {
	pdrExact := &typesv1.ProfileDataRequired{
		Opens: fieldReqPatterns(exactPattern("/bin/sh")),
	}
	pdrAll := &typesv1.ProfileDataRequired{
		Opens: fieldReqAll(),
	}

	rules := []typesv1.Rule{
		makeRule(pdrExact),
		makeRule(pdrAll),
	}
	spec := CompileSpec(rules)

	assert.True(t, spec.Opens.All, "All=true should take precedence over exact patterns")
	assert.True(t, spec.Opens.InUse, "field should be in use")
}

// TestCompileSpec_UnionAcrossRules verifies that patterns from multiple rules are
// unioned: both exact and prefix patterns from different rules appear in the spec.
func TestCompileSpec_UnionAcrossRules(t *testing.T) {
	rule1 := makeRule(&typesv1.ProfileDataRequired{
		Opens: fieldReqPatterns(exactPattern("/bin/sh")),
	})
	rule2 := makeRule(&typesv1.ProfileDataRequired{
		Opens: fieldReqPatterns(prefixPattern("/usr/")),
	})

	spec := CompileSpec([]typesv1.Rule{rule1, rule2})

	require.NotNil(t, spec.Opens.Exact, "exact map should not be nil")
	_, hasExact := spec.Opens.Exact["/bin/sh"]
	assert.True(t, hasExact, "exact /bin/sh should be present after union")
	assert.Contains(t, spec.Opens.Prefixes, "/usr/", "prefix /usr/ should be present after union")
	assert.True(t, spec.Opens.InUse)
}

// TestCompileSpec_BuildsMatchers verifies that a spec with prefixes has a
// non-nil PrefixMatcher that correctly matches.
func TestCompileSpec_BuildsMatchers(t *testing.T) {
	rule := makeRule(&typesv1.ProfileDataRequired{
		Opens: fieldReqPatterns(prefixPattern("/bin/")),
	})
	spec := CompileSpec([]typesv1.Rule{rule})

	require.NotNil(t, spec.Opens.PrefixMatcher, "PrefixMatcher should be built from prefix patterns")
	assert.True(t, spec.Opens.PrefixMatcher.HasMatch("/bin/sh"), "PrefixMatcher should match /bin/sh")
	assert.False(t, spec.Opens.PrefixMatcher.HasMatch("/etc/passwd"), "PrefixMatcher should not match /etc/passwd")
}

// TestCompileSpec_SuffixMatcher verifies that a spec with suffixes has a
// non-nil SuffixMatcher that correctly matches.
func TestCompileSpec_SuffixMatcher(t *testing.T) {
	rule := makeRule(&typesv1.ProfileDataRequired{
		Opens: fieldReqPatterns(suffixPattern(".conf")),
	})
	spec := CompileSpec([]typesv1.Rule{rule})

	require.NotNil(t, spec.Opens.SuffixMatcher, "SuffixMatcher should be built from suffix patterns")
	assert.True(t, spec.Opens.SuffixMatcher.HasMatch("/etc/app.conf"), "SuffixMatcher should match /etc/app.conf")
	assert.False(t, spec.Opens.SuffixMatcher.HasMatch("/etc/passwd"), "SuffixMatcher should not match /etc/passwd")
}

// TestCompileSpec_DeduplicatesPatterns verifies that duplicate patterns from
// multiple rules appear only once in the final spec.
func TestCompileSpec_DeduplicatesPatterns(t *testing.T) {
	rule1 := makeRule(&typesv1.ProfileDataRequired{
		Opens: fieldReqPatterns(prefixPattern("/bin/")),
	})
	rule2 := makeRule(&typesv1.ProfileDataRequired{
		Opens: fieldReqPatterns(prefixPattern("/bin/")),
	})

	spec := CompileSpec([]typesv1.Rule{rule1, rule2})

	count := 0
	for _, p := range spec.Opens.Prefixes {
		if p == "/bin/" {
			count++
		}
	}
	assert.Equal(t, 1, count, "duplicate prefix /bin/ should appear only once after dedup")
}

// TestCompileSpec_MultipleSurfaces verifies that multiple surfaces from a single
// rule are independently compiled.
func TestCompileSpec_MultipleSurfaces(t *testing.T) {
	rule := makeRule(&typesv1.ProfileDataRequired{
		Opens:    fieldReqPatterns(exactPattern("/bin/sh")),
		Execs:    fieldReqAll(),
		Syscalls: fieldReqPatterns(containsPattern("read")),
	})
	spec := CompileSpec([]typesv1.Rule{rule})

	assert.True(t, spec.Opens.InUse)
	assert.False(t, spec.Opens.All)
	assert.True(t, spec.Execs.InUse)
	assert.True(t, spec.Execs.All)
	assert.True(t, spec.Syscalls.InUse)
	assert.Contains(t, spec.Syscalls.Contains, "read")
}
