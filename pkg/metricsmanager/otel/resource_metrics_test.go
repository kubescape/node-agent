package otelmetrics

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSelfCgroupV2(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
		wantOK  bool
	}{
		{"host ns full path", "0::/kubepods.slice/kubepods-burstable.slice/pod.slice/cri-containerd-abc.scope", "/kubepods.slice/kubepods-burstable.slice/pod.slice/cri-containerd-abc.scope", true},
		{"private ns root", "0::/", "/", true},
		{"v1 lines only", "12:memory:/kubepods/pod\n11:cpu:/kubepods/pod", "", false},
		{"empty", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseSelfCgroupV2(tt.content)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantOK, ok)
		})
	}
}

// TestNamespaceRootJoin documents that the "0::/" namespace-root case collapses
// to cgroupRoot itself — the sidecar's own-namespaced-mount read path.
func TestNamespaceRootJoin(t *testing.T) {
	rel, ok := parseSelfCgroupV2("0::/")
	require.True(t, ok)
	assert.Equal(t, "/sys/fs/cgroup", filepath.Join(cgroupRoot, rel))
}

func TestParseCgroupMemValue(t *testing.T) {
	assert.Equal(t, int64(295608320), parseCgroupMemValue("295608320\n"))
	assert.Equal(t, int64(0), parseCgroupMemValue("max"), "cgroupv2 unlimited sentinel → 0")
	assert.Equal(t, int64(0), parseCgroupMemValue(""))
	assert.Equal(t, int64(0), parseCgroupMemValue("garbage"))
	assert.Equal(t, int64(766509056), parseCgroupMemValue("  766509056  "))
}

// TestFindCgroupScopeDir builds a fake cgroup tree mirroring the real EKS
// layout and asserts we locate the scope dir by container ID.
func TestFindCgroupScopeDir(t *testing.T) {
	const id = "e75962bca00d51fae3534887fbbd77b012464637c93b3be3f397dfa30a2eb8be"
	root := t.TempDir()
	scope := filepath.Join(root, "kubepods.slice", "kubepods-besteffort.slice",
		"kubepods-besteffort-poduid.slice", "cri-containerd-"+id+".scope")
	require.NoError(t, os.MkdirAll(scope, 0o755))
	// A sibling scope for a different container must not match.
	other := filepath.Join(root, "kubepods.slice", "cri-containerd-"+
		"1111111111111111111111111111111111111111111111111111111111111111.scope")
	require.NoError(t, os.MkdirAll(other, 0o755))

	got := findCgroupScopeDir(root, id)
	assert.Equal(t, scope, got)

	assert.Empty(t, findCgroupScopeDir(root, "deadbeef"), "unknown id → no match")
}

// TestResolveCgroupMemoryPaths_FastPath verifies the /proc/self/cgroup join
// path is preferred when memory.current exists there. We can't override
// /proc/self/cgroup, so this exercises the helper composition indirectly via
// the fallback resolution against a fake tree.
func TestReadCgroupMem_EndToEndFakeTree(t *testing.T) {
	const id = "abc1230000000000000000000000000000000000000000000000000000000000"
	root := t.TempDir()
	scope := filepath.Join(root, "kubepods.slice", "cri-containerd-"+id+".scope")
	require.NoError(t, os.MkdirAll(scope, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(scope, "memory.current"), []byte("123456\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(scope, "memory.max"), []byte("999999\n"), 0o644))

	dir := findCgroupScopeDir(root, id)
	require.NotEmpty(t, dir)

	cur := parseCgroupMemValue(readFileString(filepath.Join(dir, "memory.current")))
	max := parseCgroupMemValue(readFileString(filepath.Join(dir, "memory.max")))
	assert.Equal(t, int64(123456), cur)
	assert.Equal(t, int64(999999), max)
}
