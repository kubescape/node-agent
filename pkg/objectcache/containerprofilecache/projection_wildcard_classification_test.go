package containerprofilecache

import (
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProjectField_StarPathRoutesToPatterns pins that a path-surface opens
// entry containing the "*" WildcardIdentifier is classified as a Pattern,
// not a literal Value. Regression guard: containsDynamicSegment previously
// recognised only "⋯", silently routing "/etc/ssl/*" into Values.
func TestProjectField_StarPathRoutesToPatterns(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		Spec: v1beta1.ContainerProfileSpec{
			Opens: []v1beta1.OpenCalls{{Path: "/etc/ssl/*"}, {Path: "/etc/ld.so.cache"}},
		},
	}
	pcp := Apply(nil, cp, nil) // nil spec => pass-through (All=true)

	require.Contains(t, pcp.Opens.Patterns, "/etc/ssl/*",
		"a '*'-bearing path entry must be a Pattern")
	_, inValues := pcp.Opens.Values["/etc/ssl/*"]
	assert.False(t, inValues, "'*'-bearing path entry must NOT be a literal Value")
	_, cacheInValues := pcp.Opens.Values["/etc/ld.so.cache"]
	assert.True(t, cacheInValues, "a literal path entry stays a Value")
}

// TestProjectField_StarExecPathRoutesToPatterns pins the same classification
// for the Execs surface: exec paths route through the same path-surface
// projection as opens, so a "*"-bearing exec path must be a Pattern too.
// The classifier fix applied to every path surface, but only Opens had a
// pinning test.
func TestProjectField_StarExecPathRoutesToPatterns(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		Spec: v1beta1.ContainerProfileSpec{
			Execs: []v1beta1.ExecCalls{
				{Path: "/usr/bin/*", Args: []string{"/usr/bin/*"}},
				{Path: "/usr/bin/redis-cli", Args: []string{"/usr/bin/redis-cli", "ping"}},
				{Path: "/opt/⋯/agent", Args: []string{"/opt/⋯/agent"}},
			},
		},
	}
	pcp := Apply(nil, cp, nil) // nil spec => pass-through (All=true)

	require.Contains(t, pcp.Execs.Patterns, "/usr/bin/*",
		"a '*'-bearing exec path must be a Pattern")
	_, starInValues := pcp.Execs.Values["/usr/bin/*"]
	assert.False(t, starInValues, "'*'-bearing exec path must NOT be a literal Value")

	require.Contains(t, pcp.Execs.Patterns, "/opt/⋯/agent",
		"a '⋯'-bearing exec path must be a Pattern")

	_, literalInValues := pcp.Execs.Values["/usr/bin/redis-cli"]
	assert.True(t, literalInValues, "a literal exec path stays a Value")
}
