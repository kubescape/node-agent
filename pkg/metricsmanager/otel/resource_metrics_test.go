package otelmetrics

import (
	"os"
	"path/filepath"
	"strconv"
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
	// The resolver only accepts a candidate that is a real memory-controller
	// cgroup (see findCgroupScopeDir), so the fixture must carry memory.current.
	require.NoError(t, os.WriteFile(filepath.Join(scope, "memory.current"), []byte("123\n"), 0o644))
	// A sibling scope for a different container must not match.
	other := filepath.Join(root, "kubepods.slice", "cri-containerd-"+
		"1111111111111111111111111111111111111111111111111111111111111111.scope")
	require.NoError(t, os.MkdirAll(other, 0o755))

	got := findCgroupScopeDir(root, id)
	assert.Equal(t, scope, got)

	assert.Empty(t, findCgroupScopeDir(root, "deadbeef"), "unknown id → no match")
}

func TestScopeNameMatchesID(t *testing.T) {
	const id = "e75962bca00d51fae3534887fbbd77b012464637c93b3be3f397dfa30a2eb8be"
	tests := []struct {
		name    string
		dirName string
		id      string
		want    bool
	}{
		{"containerd exact", "cri-containerd-" + id + ".scope", id, true},
		{"docker exact", "docker-" + id + ".scope", id, true},
		{"crio exact", "crio-" + id + ".scope", id, true},
		{"bare id", id + ".scope", id, true},
		{"longer id with query as prefix", "cri-containerd-" + id + "deadbeef.scope", id, false},
		{"longer id with query as suffix", "cri-containerd-deadbeef" + id + ".scope", id, false},
		{"truncated query vs full id scope", "cri-containerd-" + id + ".scope", id[:32], false},
		{"empty id", "cri-containerd-" + id + ".scope", "", false},
		{"not a scope dir", "kubepods-burstable-pod" + id + ".slice", id, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, scopeNameMatchesID(tt.dirName, tt.id))
		})
	}
}

// TestFindCgroupScopeDir_NoSubstringFalsePositive asserts the exact-ID scope
// wins over a sibling whose (longer) ID merely contains the query as a
// substring, regardless of the order WalkDir visits them in.
func TestFindCgroupScopeDir_NoSubstringFalsePositive(t *testing.T) {
	const id = "abc1230000000000000000000000000000000000000000000000000000000000"

	mkScope := func(t *testing.T, dir, scopeName string) string {
		t.Helper()
		p := filepath.Join(dir, scopeName)
		require.NoError(t, os.MkdirAll(p, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(p, "memory.current"), []byte("1\n"), 0o644))
		return p
	}

	tests := []struct {
		name        string
		exactParent string
		decoyParent string
	}{
		{"exact visited first", "aaa.slice", "zzz.slice"},
		{"decoy visited first", "zzz.slice", "aaa.slice"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			exact := mkScope(t, filepath.Join(root, tt.exactParent), "cri-containerd-"+id+".scope")
			mkScope(t, filepath.Join(root, tt.decoyParent), "cri-containerd-"+id+"deadbeef.scope")
			assert.Equal(t, exact, findCgroupScopeDir(root, id))
		})
	}
}

// TestFindCgroupScopeDir_SkipsControllerWithoutMemoryFiles pins the H4 fix: a
// name match under a controller subtree with no memory.current must not stop
// the walk, and a cgroup-v1-only directory must not be accepted at all.
func TestFindCgroupScopeDir_SkipsControllerWithoutMemoryFiles(t *testing.T) {
	const id = "abc1230000000000000000000000000000000000000000000000000000000000"
	scopeName := "cri-containerd-" + id + ".scope"

	// "blkio" sorts before "memory", so the pre-fix resolver returned it.
	t.Run("skips decoy controller subtree", func(t *testing.T) {
		root := t.TempDir()
		decoy := filepath.Join(root, "blkio", "kubepods.slice", scopeName)
		require.NoError(t, os.MkdirAll(decoy, 0o755))
		wantDir := filepath.Join(root, "memory", "kubepods.slice", scopeName)
		require.NoError(t, os.MkdirAll(wantDir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(wantDir, "memory.current"), []byte("123\n"), 0o644))

		assert.Equal(t, wantDir, findCgroupScopeDir(root, id))
	})

	t.Run("no candidate has memory.current", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(root, "blkio", "kubepods.slice", scopeName), 0o755))
		require.NoError(t, os.MkdirAll(filepath.Join(root, "cpu", "kubepods.slice", scopeName), 0o755))

		assert.Empty(t, findCgroupScopeDir(root, id), "no memory-controller match → no path, not a wrong path")
	})

	// cgroup v1: resolveCgroupMemoryPaths hardcodes the v2 filename pair at its
	// return, so accepting a v1 directory here would yield nonexistent paths.
	t.Run("cgroupv1 filename is not accepted", func(t *testing.T) {
		root := t.TempDir()
		scope := filepath.Join(root, "memory", "kubepods.slice", scopeName)
		require.NoError(t, os.MkdirAll(scope, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(scope, "memory.usage_in_bytes"), []byte("123\n"), 0o644))

		assert.Empty(t, findCgroupScopeDir(root, id), "v1 hosts must fall through to the later strategies")
	})
}

const (
	testPodUID        = "11111111-2222-3333-4444-555555555555"
	testPodUIDEscaped = "11111111_2222_3333_4444_555555555555"
	testNodeAgentID   = "abc1230000000000000000000000000000000000000000000000000000000000"
	testClamavID      = "def4560000000000000000000000000000000000000000000000000000000000"
	testSBOMScannerID = "0987650000000000000000000000000000000000000000000000000000000000"
)

// mkPodCgroupTree creates <root>/<parentRel> holding parentFiles, with one
// ".scope" child per container ID (each a valid memory-controller cgroup).
// Returns the parent (pod slice) directory.
func mkPodCgroupTree(t *testing.T, root, parentRel string, parentFiles map[string]string, containerIDs ...string) string {
	t.Helper()
	parent := filepath.Join(root, parentRel)
	require.NoError(t, os.MkdirAll(parent, 0o755))
	for name, content := range parentFiles {
		require.NoError(t, os.WriteFile(filepath.Join(parent, name), []byte(content), 0o644))
	}
	for i, id := range containerIDs {
		scope := filepath.Join(parent, "cri-containerd-"+id+".scope")
		require.NoError(t, os.MkdirAll(scope, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(scope, "memory.current"),
			[]byte(strconv.Itoa(100000*(i+2))+"\n"), 0o644))
	}
	return parent
}

// TestResolvePodCgroupMemoryPaths asserts the resolver reads the pod slice
// itself — a value distinct from every child scope and from their sum — and
// that the result does not depend on how many child scopes exist.
func TestResolvePodCgroupMemoryPaths(t *testing.T) {
	parentRel := filepath.Join("kubepods.slice", "kubepods-burstable.slice",
		"kubepods-burstable-pod"+testPodUIDEscaped+".slice")
	podFiles := map[string]string{"memory.current": "900000\n", "memory.max": "1500000\n"}

	assertPodRead := func(t *testing.T, root, podSlice string) {
		t.Helper()
		cur, max := resolvePodCgroupMemoryPathsUnder(root, testNodeAgentID, testPodUID)
		require.Equal(t, filepath.Join(podSlice, "memory.current"), cur)
		require.Equal(t, filepath.Join(podSlice, "memory.max"), max)
		assert.Equal(t, int64(900000), parseCgroupMemValue(readFileString(cur)))
		assert.Equal(t, int64(1500000), parseCgroupMemValue(readFileString(max)))
	}

	t.Run("three child scopes", func(t *testing.T) {
		root := t.TempDir()
		podSlice := mkPodCgroupTree(t, root, parentRel, podFiles,
			testNodeAgentID, testClamavID, testSBOMScannerID)
		assertPodRead(t, root, podSlice)
	})

	t.Run("one child scope", func(t *testing.T) {
		root := t.TempDir()
		podSlice := mkPodCgroupTree(t, root, parentRel, podFiles, testNodeAgentID)
		assertPodRead(t, root, podSlice)
	})
}

func TestResolvePodCgroupMemoryPaths_Guards(t *testing.T) {
	podFiles := map[string]string{"memory.current": "900000\n", "memory.max": "1500000\n"}

	t.Run("empty container id", func(t *testing.T) {
		root := t.TempDir()
		mkPodCgroupTree(t, root, filepath.Join("kubepods.slice", "kubepods-burstable-pod"+testPodUIDEscaped+".slice"),
			podFiles, testNodeAgentID)
		cur, max := resolvePodCgroupMemoryPathsUnder(root, "", testPodUID)
		assert.Empty(t, cur)
		assert.Empty(t, max)
	})

	t.Run("scope directly under root", func(t *testing.T) {
		root := t.TempDir()
		mkPodCgroupTree(t, root, ".", podFiles, testNodeAgentID)
		cur, max := resolvePodCgroupMemoryPathsUnder(root, testNodeAgentID, testPodUID)
		assert.Empty(t, cur, "must never escape above the cgroup root")
		assert.Empty(t, max)
	})

	t.Run("pod slice missing memory.current", func(t *testing.T) {
		root := t.TempDir()
		mkPodCgroupTree(t, root, filepath.Join("kubepods.slice", "kubepods-burstable-pod"+testPodUIDEscaped+".slice"),
			nil, testNodeAgentID)
		cur, max := resolvePodCgroupMemoryPathsUnder(root, testNodeAgentID, testPodUID)
		assert.Empty(t, cur)
		assert.Empty(t, max)
	})

	t.Run("cgroupv1 pod slice", func(t *testing.T) {
		root := t.TempDir()
		mkPodCgroupTree(t, root, filepath.Join("kubepods.slice", "kubepods-burstable-pod"+testPodUIDEscaped+".slice"),
			map[string]string{"memory.usage_in_bytes": "900000\n", "memory.limit_in_bytes": "1500000\n"}, testNodeAgentID)
		cur, max := resolvePodCgroupMemoryPathsUnder(root, testNodeAgentID, testPodUID)
		assert.Empty(t, cur, "v1 pod slice must fail to zero, not to nonexistent v2 paths")
		assert.Empty(t, max)
	})

	// Both halves of the name guard's truth table. The reject set is the
	// dangerous one: on a real node kubepods.slice and the QoS slices do have a
	// memory.current, so the file-existence check alone would not stop them.
	t.Run("parent name shapes", func(t *testing.T) {
		tests := []struct {
			baseName string
			accept   bool
		}{
			{"pod" + testPodUIDEscaped + ".slice", true},
			{"kubepods-pod" + testPodUIDEscaped + ".slice", true},
			{"kubepods-burstable-pod" + testPodUIDEscaped + ".slice", true},
			{"kubepods-besteffort-pod" + testPodUIDEscaped + ".slice", true},
			// Custom kubelet --cgroup-root: an extra segment before "kubepods-".
			{"kubelet-kubepods-burstable-pod" + testPodUIDEscaped + ".slice", true},
			{"kubepods.slice", false},
			{"kubepods-burstable.slice", false},
			{"kubepods-besteffort.slice", false},
			{"system.slice", false},
		}
		for _, tt := range tests {
			t.Run(tt.baseName, func(t *testing.T) {
				root := t.TempDir()
				parent := mkPodCgroupTree(t, root, filepath.Join("kubepods.slice", tt.baseName),
					podFiles, testNodeAgentID)
				cur, max := resolvePodCgroupMemoryPathsUnder(root, testNodeAgentID, testPodUID)
				if tt.accept {
					assert.Equal(t, filepath.Join(parent, "memory.current"), cur)
					assert.Equal(t, filepath.Join(parent, "memory.max"), max)
					return
				}
				assert.Empty(t, cur)
				assert.Empty(t, max)
			})
		}
	})
}

func TestResolvePodCgroupMemoryPaths_PodUIDVerification(t *testing.T) {
	const otherUIDEscaped = "99999999_8888_7777_6666_555555555555"
	podFiles := map[string]string{"memory.current": "900000\n", "memory.max": "1500000\n"}

	tests := []struct {
		name      string
		sliceName string
		ownPodUID string
		accept    bool
	}{
		{"matching uid", "kubepods-burstable-pod" + testPodUIDEscaped + ".slice", testPodUID, true},
		{"matching uid, bare kubepods prefix", "kubepods-pod" + testPodUIDEscaped + ".slice", testPodUID, true},
		{"matching uid, custom cgroup-root prefix", "kubelet-kubepods-burstable-pod" + testPodUIDEscaped + ".slice", testPodUID, true},
		{"different well-formed uid", "kubepods-burstable-pod" + otherUIDEscaped + ".slice", testPodUID, false},
		{"different well-formed uid, custom cgroup-root prefix", "kubelet-kubepods-burstable-pod" + otherUIDEscaped + ".slice", testPodUID, false},
		{"different well-formed uid, bare kubepods prefix", "kubepods-pod" + otherUIDEscaped + ".slice", testPodUID, false},
		{"unknown uid falls back to the name guard", "kubepods-burstable-pod" + testPodUIDEscaped + ".slice", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			parent := mkPodCgroupTree(t, root, filepath.Join("kubepods.slice", tt.sliceName),
				podFiles, testNodeAgentID)
			cur, max := resolvePodCgroupMemoryPathsUnder(root, testNodeAgentID, tt.ownPodUID)
			if tt.accept {
				assert.Equal(t, filepath.Join(parent, "memory.current"), cur)
				assert.Equal(t, filepath.Join(parent, "memory.max"), max)
				return
			}
			assert.Empty(t, cur, "a well-formed but wrong pod UID must be rejected")
			assert.Empty(t, max)
		})
	}
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
