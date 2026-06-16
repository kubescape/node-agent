package containerprofilecache

import (
	"context"
	"testing"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestTest32_RealProjectionPipeline drives the REAL ContainerProfileCache
// projection — base CP (404 / synthetic) + the curl-32-overlay user AP,
// exactly as Test_32 deploys it — through addContainer → tryPopulateEntry →
// projectUserProfiles → Apply → extractExecsByPath, with NO mock shortcut.
//
// It then dumps the materialised ExecsByPath and applies the same
// CompareExecArgs walk that wasExecutedWithArgs performs, so we can see the
// GROUND TRUTH the production rule evaluator would see — answering whether
// R0040 silence comes from the projection (missing/empty vector) or from
// somewhere else (capture-side args).
func TestTest32_RealProjectionPipeline(t *testing.T) {
	const wild = dynamicpathdetector.ExecArgsWildcard

	// curl-32-overlay user AP. Container name MUST be "nginx" to match the
	// InstanceID that primeSharedData/eventContainer build. The argv shapes
	// mirror Test_32's profile.
	userAP := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "curl-32-overlay", Namespace: "default", ResourceVersion: "1"},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{{
				Name: "nginx",
				Execs: []v1beta1.ExecCalls{
					{Path: "/bin/busybox", Args: []string{"/bin/sleep", wild}},
					{Path: "/bin/busybox", Args: []string{"/bin/sh", "-c", wild}},
					{Path: "/bin/busybox", Args: []string{"/bin/echo", "hello", wild}},
				},
			}},
		},
	}

	// Base CP 404 → cache synthesises an empty base, then overlays the user AP.
	client := &fakeProfileClient{cp: nil, cpErr: assertErrNotFound("no-base"), ap: userAP}
	c, k8s := newTestCache(t, client)
	c.SetProjectionSpec(objectcache.RuleProjectionSpec{
		Execs: objectcache.FieldSpec{InUse: true, All: true},
		Hash:  "test32-real",
	})

	id := "container-test32"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
	ct := eventContainer(id)
	ct.K8s.PodLabels = map[string]string{helpersv1.UserDefinedProfileMetadataKey: "curl-32-overlay"}
	require.NoError(t, c.addContainer(ct, context.Background()))

	pcp := c.GetProjectedContainerProfile(id)
	require.NotNil(t, pcp, "real projection must produce an entry")

	// GROUND TRUTH dump.
	t.Logf("Execs.Values keys: %v", keysOf(pcp.Execs.Values))
	t.Logf("Execs.Patterns: %v", pcp.Execs.Patterns)
	t.Logf("ExecsByPath[/bin/busybox] = %#v", pcp.ExecsByPath["/bin/busybox"])
	t.Logf("ExecsByPath full = %#v", pcp.ExecsByPath)

	// Replicate the exact matcher walk from wasExecutedWithArgs (post-fix:
	// empty vector matches only empty runtime; non-empty via CompareExecArgs).
	match := func(pathStr string, runtimeArgs []string) bool {
		if _, ok := pcp.Execs.Values[pathStr]; ok {
			if vectors, ok := pcp.ExecsByPath[pathStr]; ok {
				for _, pv := range vectors {
					if len(pv) == 0 {
						if len(runtimeArgs) == 0 {
							return true
						}
						continue
					}
					if dynamicpathdetector.CompareExecArgs(pv, runtimeArgs) {
						return true
					}
				}
				return false
			}
			return true // State 2: back-compat no-constraint
		}
		return false
	}

	// /bin/busybox must be present in Values (R0001 stays silent — path known).
	_, busyboxKnown := pcp.Execs.Values["/bin/busybox"]
	require.True(t, busyboxKnown, "path /bin/busybox must be in Execs.Values (R0001 precondition)")
	require.NotNil(t, pcp.ExecsByPath["/bin/busybox"], "ExecsByPath must carry the busybox vectors (else back-compat returns true and R0040 never fires)")

	cases := []struct {
		name string
		args []string
		want bool // was_executed_with_args result; false => R0040 fires
	}{
		{"sh -c matches", []string{"/bin/sh", "-c", "echo hi"}, true},
		{"sh -x -c mismatches", []string{"/bin/sh", "-x", "-c", "echo hi"}, false},
		{"echo hello matches", []string{"/bin/echo", "hello", "world", "from", "test"}, true},
		{"echo goodbye mismatches", []string{"/bin/echo", "goodbye", "world"}, false},
	}
	for _, tc := range cases {
		got := match("/bin/busybox", tc.args)
		assert.Equalf(t, tc.want, got,
			"real pipeline: was_executed_with_args(/bin/busybox, %v) = %v, want %v", tc.args, got, tc.want)
	}
}

func keysOf(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestTest32_BaseCPBareVectorPoisonsR0040 reproduces the ACTUAL Test_32
// production failure through the real projection pipeline.
//
// In production the curl-32 pod's `sleep infinity` startup exec is recorded
// into the consolidated base ContainerProfile as a /bin/busybox entry with
// empty/no args (the recorder stores Path + the observed argv; for a bare
// applet exec the args surface collapses to empty). That base CP is then
// overlaid with the user-defined curl-32-overlay AP, so the MERGED profile
// carries BOTH the bare /bin/busybox vector AND the three constrained ones.
//
// dynamicpathdetector.CompareExecArgs treats the empty bare vector as "no
// argv constraint" → returns true for ANY runtime args. When the matcher
// ORs across vectors, that one empty vector makes was_executed_with_args
// return true for every exec → R0040 never fires. This is the silence
// entlein observed on echo_goodbye / sh_dash_x while echo_hello / sh_dash_c
// (which legitimately match) stayed green.
//
// The test drives the REAL projectUserProfiles → Apply merge, then shows the
// raw-CompareExecArgs walk (deployed behaviour) returns the WRONG answer and
// the MatchExecArgs (strict) walk (the fix) returns the RIGHT answer.
func TestTest32_BaseCPBareVectorPoisonsR0040(t *testing.T) {
	const wild = dynamicpathdetector.ExecArgsWildcard

	// Base consolidated CP: the recorded /bin/busybox startup exec, bare args.
	baseCP := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: "replicaset-curl-32-curl", Namespace: "default", ResourceVersion: "5",
			Annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Full,
				helpersv1.StatusMetadataKey:     helpersv1.Completed,
			},
		},
		Spec: v1beta1.ContainerProfileSpec{
			Execs: []v1beta1.ExecCalls{
				{Path: "/bin/busybox", Args: nil}, // bare recorder entry — the poison
			},
		},
	}
	userAP := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "curl-32-overlay", Namespace: "default", ResourceVersion: "1"},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{{
				Name: "nginx",
				Execs: []v1beta1.ExecCalls{
					{Path: "/bin/busybox", Args: []string{"/bin/sleep", wild}},
					{Path: "/bin/busybox", Args: []string{"/bin/sh", "-c", wild}},
					{Path: "/bin/busybox", Args: []string{"/bin/echo", "hello", wild}},
				},
			}},
		},
	}

	client := &fakeProfileClient{cp: baseCP, ap: userAP}
	c, k8s := newTestCache(t, client)
	c.SetProjectionSpec(objectcache.RuleProjectionSpec{
		Execs: objectcache.FieldSpec{InUse: true, All: true},
		Hash:  "test32-poison",
	})

	id := "container-test32-poison"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
	ct := eventContainer(id)
	ct.K8s.PodLabels = map[string]string{helpersv1.UserDefinedProfileMetadataKey: "curl-32-overlay"}
	require.NoError(t, c.addContainer(ct, context.Background()))

	pcp := c.GetProjectedContainerProfile(id)
	require.NotNil(t, pcp)
	vectors := pcp.ExecsByPath["/bin/busybox"]
	t.Logf("MERGED ExecsByPath[/bin/busybox] = %#v", vectors)

	// Confirm the merged profile really does carry a bare (empty) vector
	// alongside the constrained ones — the production-faithful shape.
	hasBare := false
	for _, v := range vectors {
		if len(v) == 0 {
			hasBare = true
		}
	}
	require.True(t, hasBare, "merged profile must contain the bare /bin/busybox vector (the poison)")
	require.GreaterOrEqual(t, len(vectors), 4, "bare + 3 constrained vectors")

	rawWalk := func(runtimeArgs []string) bool { // deployed b94913b3 behaviour
		for _, pv := range vectors {
			if dynamicpathdetector.CompareExecArgs(pv, runtimeArgs) {
				return true
			}
		}
		return false
	}
	fixedWalk := func(runtimeArgs []string) bool { // MatchExecArgs(strict) behaviour
		for _, pv := range vectors {
			if len(pv) == 0 {
				if len(runtimeArgs) == 0 {
					return true
				}
				continue
			}
			if dynamicpathdetector.CompareExecArgs(pv, runtimeArgs) {
				return true
			}
		}
		return false
	}

	echoGoodbye := []string{"/bin/echo", "goodbye", "world"}
	shDashX := []string{"/bin/sh", "-x", "-c", "echo hi"}

	// Deployed behaviour: the empty vector poisons the OR → returns true →
	// R0040 stays silent. This is the bug.
	assert.True(t, rawWalk(echoGoodbye), "DEPLOYED: empty vector wrongly matches echo goodbye (reproduces R0040 silence)")
	assert.True(t, rawWalk(shDashX), "DEPLOYED: empty vector wrongly matches sh -x -c (reproduces R0040 silence)")

	// Fixed behaviour: empty vector matches only empty runtime → mismatches
	// fall through → returns false → R0040 fires.
	assert.False(t, fixedWalk(echoGoodbye), "FIXED: echo goodbye no longer matches → R0040 fires")
	assert.False(t, fixedWalk(shDashX), "FIXED: sh -x -c no longer matches → R0040 fires")
	// Legitimate matches still hold under the fix.
	assert.True(t, fixedWalk([]string{"/bin/echo", "hello", "world"}), "FIXED: echo hello still matches")
	assert.True(t, fixedWalk([]string{"/bin/sh", "-c", "echo hi"}), "FIXED: sh -c still matches")
}
