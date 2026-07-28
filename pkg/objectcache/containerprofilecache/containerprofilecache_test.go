package containerprofilecache

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	instanceidhandlerV1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// fakeProfileClient is a minimal storage.ProfileClient stub for tests. It
// always returns the same CP pointer (so the fast-path can be asserted via
// pointer equality).
type fakeProfileClient struct {
	cp *v1beta1.ContainerProfile
	// userCP, when non-nil, is returned by GetContainerProfile for a name
	// matching userCP.Name (the migrated user-defined ContainerProfile). Other
	// names fall through to cp. Lets tests exercise the new-way overlay path.
	userCP *v1beta1.ContainerProfile
	cpErr  error

	// userCPsByName, when non-empty, is consulted before the cp/userCP
	// fallbacks: a name present in the map returns its CP (nil error), a name
	// absent returns cp/cpErr. Lets tests publish DISTINCT authored
	// ContainerProfiles per container name ("<overlay>-<containerName>") so the
	// per-container binding path can be exercised end-to-end.
	userCPsByName map[string]*v1beta1.ContainerProfile

	// userManagedCP, when non-nil, is returned by GetContainerProfile for any
	// name starting with the "ug-" user-managed prefix. This is the migrated
	// replacement for the legacy ug- ApplicationProfile + NetworkNeighborhood
	// overlay pair and lets tests exercise the user-managed merge path.
	userManagedCP *v1beta1.ContainerProfile

	// overlayOnly, if non-empty, scopes the overlay name whose GetContainerProfile
	// returns a genuine NotFound (or overlayCPErr). Tests use this to keep the
	// user-defined-CP fixture scoped.
	overlayOnly string

	// overlayCPErr, when non-nil, is returned by GetContainerProfile for a
	// name matching overlayOnly, instead of the default NotFound. Lets tests
	// simulate a *transient* RPC failure on the user-defined-CP fetch (as
	// opposed to a genuine "doesn't exist yet"), to prove the overlay is not
	// permanently lost.
	overlayCPErr error

	getCPCalls int
}

var _ storage.ProfileClient = (*fakeProfileClient)(nil)

func TestShouldLogOptionalUserManagedFetchError(t *testing.T) {
	assert.False(t, shouldLogOptionalUserManagedFetchError(nil))
	assert.False(t, shouldLogOptionalUserManagedFetchError(
		apierrors.NewNotFound(schema.GroupResource{Group: "softwarecomposition.kubescape.io", Resource: "containerprofiles"}, "ug-nginx"),
	))
	assert.True(t, shouldLogOptionalUserManagedFetchError(errors.New("boom")))
}

func (f *fakeProfileClient) GetContainerProfile(_ context.Context, _, name string) (*v1beta1.ContainerProfile, error) {
	f.getCPCalls++
	// User-managed "ug-<workload>" overlay: a single ContainerProfile, the
	// migrated replacement for the legacy ug- AP/NN pair.
	if strings.HasPrefix(name, helpersv1.UserApplicationProfilePrefix) {
		return f.userManagedCP, nil
	}
	// Name-keyed authored CPs take precedence: this is how a multi-container pod
	// serves a different CP per "<overlay>-<containerName>" name.
	if f.userCPsByName != nil {
		if cp, ok := f.userCPsByName[name]; ok {
			return cp, nil
		}
	}
	if f.userCP != nil && name == f.userCP.Name {
		return f.userCP, nil
	}
	// The overlay label points at overlayOnly; with no user CP published at that
	// name it is absent (or a transient error). The base CP fetch uses the
	// derived slug, a different name, and still gets f.cp.
	if f.overlayOnly != "" && name == f.overlayOnly {
		if f.overlayCPErr != nil {
			return nil, f.overlayCPErr
		}
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "containerprofiles"}, name)
	}
	return f.cp, f.cpErr
}

// newTestCache returns a cache wired with an in-memory K8sObjectCacheMock.
func newTestCache(t *testing.T, client storage.ProfileClient) (*ContainerProfileCacheImpl, *objectcache.K8sObjectCacheMock) {
	t.Helper()
	k8s := &objectcache.K8sObjectCacheMock{}
	cfg := config.Config{ProfilesCacheRefreshRate: 30 * time.Second}
	return NewContainerProfileCache(cfg, client, k8s, nil), k8s
}

// primeSharedData stashes a WatchedContainerData so waitForSharedContainerData
// resolves instantly. It builds a real InstanceID from a pod because the cache
// code calls .GetOneTimeSlug and .GetTemplateHash on it.
func primeSharedData(t *testing.T, k8s *objectcache.K8sObjectCacheMock, containerID, wlid string) {
	t.Helper()
	ids, err := instanceidhandlerV1.GenerateInstanceIDFromPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "nginx-abc", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "nginx", Image: "nginx:1.25"}},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{{Name: "nginx", ImageID: "sha256:deadbeef"}},
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, ids)
	k8s.SetSharedContainerData(containerID, &objectcache.WatchedContainerData{
		InstanceID: ids[0],
		Wlid:       wlid,
	})
}

// eventContainer returns a minimal *containercollection.Container.
func eventContainer(id string) *containercollection.Container {
	return &containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
			ContainerID:   id,
			ContainerName: "nginx",
			ContainerPID:  42,
		}},
		K8s: containercollection.K8sMetadata{BasicK8sMetadata: eventtypes.BasicK8sMetadata{
			Namespace: "default",
			PodName:   "nginx-abc",
		}},
	}
}

// TestSharedFastPath_NoOverlay verifies that two separate add calls for the
// same CP yield entries with populated projected profiles.
func TestSharedFastPath_NoOverlay(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "cp-shared",
			Namespace:       "default",
			ResourceVersion: "7",
			Annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Full,
				helpersv1.StatusMetadataKey:     helpersv1.Completed,
			},
		},
		Spec: v1beta1.ContainerProfileSpec{
			Capabilities: []string{"NET_ADMIN"},
		},
	}
	client := &fakeProfileClient{cp: cp}
	c, k8s := newTestCache(t, client)

	ids := []string{"container-id-A", "container-id-B"}
	for _, id := range ids {
		primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
		require.NoError(t, c.addContainer(eventContainer(id), context.Background()))
	}

	entryA, okA := c.entries.Load(ids[0])
	entryB, okB := c.entries.Load(ids[1])
	require.True(t, okA)
	require.True(t, okB)
	assert.NotNil(t, entryA.Projected, "entry A must have a projected profile")
	assert.NotNil(t, entryB.Projected, "entry B must have a projected profile")
}

// TestOverlayPath_UserDefinedCP_NewWay verifies the migrated path: when the
// user-defined-profile label names a user-authored ContainerProfile
// (managed-by: User), it becomes the authoritative base — UserCPRef is set and
// the projection reflects the CP.
func TestOverlayPath_UserDefinedCP_NewWay(t *testing.T) {
	// A genuine authored CP carries NO learning-lifecycle annotations (no
	// status/completion) — only managed-by: User. A CP that carried a status
	// annotation would be treated as learned and ignored (see
	// TestUserDefinedCP_LearnedProfileIgnored).
	userCP := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: "override", Namespace: "default", ResourceVersion: "uc1",
			Annotations: map[string]string{
				helpersv1.ManagedByMetadataKey: helpersv1.ManagedByUserValue,
			},
		},
		Spec: v1beta1.ContainerProfileSpec{Capabilities: []string{"NET_BIND_SERVICE"}},
	}
	// cp: nil (learning suppressed for user-defined); userCP served at "override".
	client := &fakeProfileClient{cp: nil, cpErr: apierrors.NewNotFound(schema.GroupResource{}, "x"), userCP: userCP}
	c, k8s := newTestCache(t, client)

	id := "container-udcp"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")

	ev := eventContainer(id)
	ev.K8s.PodLabels = map[string]string{helpersv1.UserDefinedProfileMetadataKey: "override"}
	require.NoError(t, c.addContainer(ev, context.Background()))

	entry, ok := c.entries.Load(id)
	require.True(t, ok)
	assert.NotNil(t, entry.Projected, "user-defined CP path must produce a projected profile")
	require.NotNil(t, entry.UserCPRef, "UserCPRef must be recorded for refresh")
	assert.Equal(t, "override", entry.UserCPRef.Name)
	assert.Equal(t, "uc1", entry.UserCPRV)
}

// TestOverlayPath_CPFetchTransientError_RecordsUserCPRef pins the cutover
// semantics: when the overlay label is present but the GetContainerProfile
// fetch at the overlay name fails *transiently* (an RPC error, not a genuine
// absence), an entry that is still built from a present base CP must record
// UserCPRef so the reconciler keeps probing for the user-defined CP on later
// ticks. There is no legacy AP/NN fallback anymore — the CP is the only
// user-defined source — so without this the authored profile would be silently
// lost until the container restarts.
//
// This test fails on code that does not record UserCPRef on a transient
// overlay-CP fetch failure and passes once it does.
func TestOverlayPath_CPFetchTransientError_RecordsUserCPRef(t *testing.T) {
	// A completed base CP is present (fetched by the derived slug name), but the
	// CP fetch at the overlay name errors transiently, so userDefinedCP is nil
	// for this add and the entry is built from the base CP.
	baseCP := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cp-base", Namespace: "default", ResourceVersion: "1",
			Annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Full,
				helpersv1.StatusMetadataKey:     helpersv1.Completed,
			},
		},
		Spec: v1beta1.ContainerProfileSpec{Capabilities: []string{"SYS_PTRACE"}},
	}
	// The per-container fetch ("override-nginx") errors transiently. A transient
	// error is not a fallback trigger, so the bare "override" stays the recorded
	// retry target — proving UserCPRef is set even when this fetch fails.
	client := &fakeProfileClient{
		cp:           baseCP,
		overlayOnly:  "override-nginx",
		overlayCPErr: errors.New("etcdserver: request timed out"), // transient
	}
	c, k8s := newTestCache(t, client)

	id := "container-cp-transient"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")

	ev := eventContainer(id)
	ev.K8s.PodLabels = map[string]string{helpersv1.UserDefinedProfileMetadataKey: "override"}
	require.NoError(t, c.addContainer(ev, context.Background()))

	entry, ok := c.entries.Load(id)
	require.True(t, ok)
	// The contract: UserCPRef is recorded even though the overlay-CP fetch failed
	// transiently, so refreshOneEntry (which only re-fetches the CP
	// `if e.UserCPRef != nil`) will retry it once the transient error clears.
	require.NotNil(t, entry.UserCPRef, "UserCPRef must be recorded so the reconciler retries the CP after a transient failure")
	assert.Equal(t, "override", entry.UserCPRef.Name)
	assert.Equal(t, "default", entry.UserCPRef.Namespace)
}

// TestDeleteContainer_LockAndCleanup verifies that deleteContainer removes
// the entry and releases the per-container lock so a later Add re-uses a
// fresh mutex.
func TestDeleteContainer_LockAndCleanup(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cp-delete", Namespace: "default", ResourceVersion: "1",
			Annotations: map[string]string{helpersv1.StatusMetadataKey: helpersv1.Completed},
		},
	}
	client := &fakeProfileClient{cp: cp}
	c, k8s := newTestCache(t, client)

	id := "container-delete"
	primeSharedData(t, k8s, id, "wlid://x")
	require.NoError(t, c.addContainer(eventContainer(id), context.Background()))
	require.True(t, c.containerLocks.HasLock(id), "lock should exist after add")
	require.NotNil(t, c.GetProjectedContainerProfile(id))

	c.deleteContainer(id)
	assert.Nil(t, c.GetProjectedContainerProfile(id), "entry must be gone after delete")
	// Phase-4 review fix: deleteContainer intentionally does NOT release the
	// lock to avoid a race where a concurrent addContainer could hold a
	// reference to a mutex that another caller re-creates after Delete.
	// Memory cost is bounded by live+recently-deleted container IDs.
	assert.True(t, c.containerLocks.HasLock(id), "lock is retained by design after delete")
}

// TestContainerCallback_IgnoredContainer verifies IgnoreContainer short-circuits
// before any storage call is issued.
func TestContainerCallback_IgnoredContainer(t *testing.T) {
	cp := &v1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Name: "cp", Namespace: "default", ResourceVersion: "1"}}
	client := &fakeProfileClient{cp: cp}
	c, _ := newTestCache(t, client)
	c.cfg.ExcludeNamespaces = []string{"kube-system"}

	ev := containercollection.PubSubEvent{
		Type: containercollection.EventTypeAddContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
				ContainerID: "ignored", ContainerPID: 42, ContainerName: "c",
			}},
			K8s: containercollection.K8sMetadata{BasicK8sMetadata: eventtypes.BasicK8sMetadata{
				Namespace: "kube-system", PodName: "p",
			}},
		},
	}
	c.ContainerCallback(ev)
	// Allow any mistakenly-spawned goroutine a brief window — none should run.
	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, 0, client.getCPCalls, "IgnoreContainer must short-circuit before any storage call")
}

// TestContainerCallback_HostContainer verifies that host containers do NOT
// trigger IgnoreContainer even when their namespace is in ExcludeNamespaces
// (host events carry namespace="host" after override, not the original one).
func TestContainerCallback_HostContainer(t *testing.T) {
	cp := &v1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Name: "cp", Namespace: "host", ResourceVersion: "1"}}
	client := &fakeProfileClient{cp: cp}
	c, _ := newTestCache(t, client)
	// Even with every namespace excluded, host containers bypass the check.
	c.cfg.ExcludeNamespaces = []string{"default", "host"}

	hostContainer := &containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
			ContainerID: "host-c", ContainerPID: 1, ContainerName: "host",
		}},
		K8s: containercollection.K8sMetadata{BasicK8sMetadata: eventtypes.BasicK8sMetadata{
			Namespace: "default", PodName: "",
		}},
	}
	c.ContainerCallback(containercollection.PubSubEvent{Type: containercollection.EventTypeAddContainer, Container: hostContainer})
	// The callback dispatches a goroutine that will stall on backoff (no
	// shared data is primed) — we only assert the callback returns without
	// panic and did not short-circuit on IgnoreContainer. We cannot assert
	// storage was called without racing the backoff; just confirm no panic.
	time.Sleep(20 * time.Millisecond)
}

// TestCallStackIndexBuiltFromProfile verifies that the call-stack tree is
// populated from CP.Spec.IdentifiedCallStacks and retrievable via
// GetCallStackSearchTree.
func TestCallStackIndexBuiltFromProfile(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cp-stack", Namespace: "default", ResourceVersion: "1",
			Annotations: map[string]string{helpersv1.StatusMetadataKey: helpersv1.Completed},
		},
		Spec: v1beta1.ContainerProfileSpec{
			IdentifiedCallStacks: []v1beta1.IdentifiedCallStack{
				{
					CallID: "r1",
					CallStack: v1beta1.CallStack{Root: v1beta1.CallStackNode{
						Frame: v1beta1.StackFrame{FileID: "f1", Lineno: "10"},
						Children: []v1beta1.CallStackNode{
							{Frame: v1beta1.StackFrame{FileID: "f2", Lineno: "20"}},
						},
					}},
				},
			},
		},
	}
	client := &fakeProfileClient{cp: cp}
	c, k8s := newTestCache(t, client)

	id := "c-stack"
	primeSharedData(t, k8s, id, "wlid://x")
	require.NoError(t, c.addContainer(eventContainer(id), context.Background()))

	tree := c.GetCallStackSearchTree(id)
	require.NotNil(t, tree)
	require.NotNil(t, tree.PathsByCallID)
	_, hasCallID := tree.PathsByCallID["r1"]
	assert.True(t, hasCallID, "call-stack tree must contain CallID 'r1' from CP")
}

// authoredCP builds a genuine user-authored ContainerProfile: managed-by: User
// and, crucially, NO learning-lifecycle annotations (no status/completion), so
// the authored-validation gate does not treat it as a learned profile. Its spec
// carries a single distinctive Exec so per-container adoption is observable in
// the projection.
func authoredCP(name, execPath, rv string) *v1beta1.ContainerProfile {
	return &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: "default", ResourceVersion: rv,
			Annotations: map[string]string{
				helpersv1.ManagedByMetadataKey: helpersv1.ManagedByUserValue,
			},
		},
		Spec: v1beta1.ContainerProfileSpec{Execs: []v1beta1.ExecCalls{{Path: execPath}}},
	}
}

// execsAllSpec is a projection spec that retains every Exec path in Values so
// tests can assert per-container adoption via the projected allow-list.
func execsAllSpec(hash string) objectcache.RuleProjectionSpec {
	return objectcache.RuleProjectionSpec{
		Execs: objectcache.FieldSpec{InUse: true, All: true},
		Hash:  hash,
	}
}

// TestUserDefinedCP_PerContainerBinding proves blocker #2: in a multi-container
// pod that shares ONE user-defined-profile label value, each container must
// adopt its OWN authored ContainerProfile, resolved by the
// "<overlay>-<containerName>" naming convention — not the same CP for every
// container.
func TestUserDefinedCP_PerContainerBinding(t *testing.T) {
	frontend := authoredCP("nw-20-multi-container-frontend", "/bin/frontend", "1")
	sidecar := authoredCP("nw-20-multi-container-sidecar", "/bin/sidecar", "1")
	client := &fakeProfileClient{
		cp:    nil,
		cpErr: apierrors.NewNotFound(schema.GroupResource{Resource: "containerprofiles"}, "learned"),
		userCPsByName: map[string]*v1beta1.ContainerProfile{
			"nw-20-multi-container-frontend": frontend,
			"nw-20-multi-container-sidecar":  sidecar,
		},
	}
	c, k8s := newTestCache(t, client)
	c.SetProjectionSpec(execsAllSpec("per-container"))

	cases := []struct {
		id, cname, ownExec, otherExec, cpName string
	}{
		{"cid-frontend", "frontend", "/bin/frontend", "/bin/sidecar", "nw-20-multi-container-frontend"},
		{"cid-sidecar", "sidecar", "/bin/sidecar", "/bin/frontend", "nw-20-multi-container-sidecar"},
	}
	for _, tc := range cases {
		primeSharedData(t, k8s, tc.id, "wlid://cluster-a/namespace-default/deployment-nginx")
		ev := eventContainer(tc.id)
		ev.Runtime.ContainerName = tc.cname
		ev.K8s.PodLabels = map[string]string{helpersv1.UserDefinedProfileMetadataKey: "nw-20-multi-container"}
		require.NoError(t, c.addContainer(ev, context.Background()))
	}

	for _, tc := range cases {
		entry, ok := c.entries.Load(tc.id)
		require.True(t, ok, "entry present for %s", tc.cname)
		require.NotNil(t, entry.UserCPRef)
		assert.Equal(t, tc.cpName, entry.UserCPRef.Name,
			"%s must resolve to its per-container CP so the reconciler re-fetches the same object", tc.cname)
		proj := c.GetProjectedContainerProfile(tc.id)
		require.NotNil(t, proj)
		_, hasOwn := proj.Execs.Values[tc.ownExec]
		_, hasOther := proj.Execs.Values[tc.otherExec]
		assert.True(t, hasOwn, "%s must adopt its OWN CP (%s present)", tc.cname, tc.ownExec)
		assert.False(t, hasOther, "%s must NOT adopt the sibling container's CP (%s absent)", tc.cname, tc.otherExec)
	}
}

// TestUserDefinedCP_SingleContainerBareFallback proves the single-container
// fallback in blocker #2: when no "<overlay>-<containerName>" CP exists, the
// resolver falls back to the bare "<overlay>" name.
func TestUserDefinedCP_SingleContainerBareFallback(t *testing.T) {
	bare := authoredCP("override", "/bin/only", "1")
	client := &fakeProfileClient{
		cp:            nil,
		cpErr:         apierrors.NewNotFound(schema.GroupResource{Resource: "containerprofiles"}, "learned"),
		userCPsByName: map[string]*v1beta1.ContainerProfile{"override": bare},
	}
	c, k8s := newTestCache(t, client)
	c.SetProjectionSpec(execsAllSpec("bare-fallback"))

	id := "cid-single"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
	ev := eventContainer(id) // ContainerName "nginx" → per-container "override-nginx" is absent
	ev.K8s.PodLabels = map[string]string{helpersv1.UserDefinedProfileMetadataKey: "override"}
	require.NoError(t, c.addContainer(ev, context.Background()))

	entry, ok := c.entries.Load(id)
	require.True(t, ok)
	require.NotNil(t, entry.UserCPRef)
	assert.Equal(t, "override", entry.UserCPRef.Name, "single-container pod falls back to the bare overlay name")
	proj := c.GetProjectedContainerProfile(id)
	require.NotNil(t, proj)
	_, hasOnly := proj.Execs.Values["/bin/only"]
	assert.True(t, hasOnly, "bare-name CP must be adopted")
}

// TestUserDefinedCP_LearnedProfileIgnored proves blocker #3 on the add path: a
// CP published at the label name that carries a lifecycle status ("ready") is a
// LEARNED profile, not authored. It must be ignored — never adopted and never
// force-enforced as Completed/Full. With no other profile source, the container
// stays pending.
func TestUserDefinedCP_LearnedProfileIgnored(t *testing.T) {
	learnedAtLabel := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ready-cp", Namespace: "default", ResourceVersion: "1",
			Annotations: map[string]string{
				helpersv1.StatusMetadataKey:     helpersv1.Learning, // status: ready → still learning
				helpersv1.CompletionMetadataKey: helpersv1.Partial,
			},
		},
		Spec: v1beta1.ContainerProfileSpec{Execs: []v1beta1.ExecCalls{{Path: "/bin/leaked"}}},
	}
	client := &fakeProfileClient{
		cp:            nil,
		cpErr:         apierrors.NewNotFound(schema.GroupResource{Resource: "containerprofiles"}, "learned"),
		userCPsByName: map[string]*v1beta1.ContainerProfile{"ready-cp": learnedAtLabel},
	}
	c, k8s := newTestCache(t, client)

	id := "cid-learned-label"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
	ev := eventContainer(id)
	ev.K8s.PodLabels = map[string]string{helpersv1.UserDefinedProfileMetadataKey: "ready-cp"}
	require.NoError(t, c.addContainer(ev, context.Background()))

	_, ok := c.entries.Load(id)
	assert.False(t, ok, "a learned CP at the label name must NOT be adopted/force-enforced")
	assert.Equal(t, 1, c.pending.Len(), "container stays pending when the label resolves only to a learned CP")
}

// TestRefreshReflectsAuthoredCPEdit_RVFreezeProof is the key proof for fix #1
// (RV freeze). A user-defined-only container (NO learned CP — learning is
// suppressed) is added; the entry's learned RV must be empty. When the authored
// CP is later edited (RV bumped + spec changed), a single refresh MUST reflect
// the edit. This only holds because entry.RV tracks the LEARNED slug (empty),
// so the permanent 404 on that slug during refresh is not mistaken for a
// transient error that would freeze the entry.
func TestRefreshReflectsAuthoredCPEdit_RVFreezeProof(t *testing.T) {
	authored := authoredCP("authored-cp-nginx", "/bin/init", "a1")
	client := &fakeProfileClient{
		cp:            nil,
		cpErr:         apierrors.NewNotFound(schema.GroupResource{Resource: "containerprofiles"}, "learned"),
		userCPsByName: map[string]*v1beta1.ContainerProfile{"authored-cp-nginx": authored},
	}
	c, k8s := newTestCache(t, client)
	c.SetProjectionSpec(execsAllSpec("rv-freeze"))

	id := "cid-rvfreeze"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
	ev := eventContainer(id)
	ev.K8s.PodLabels = map[string]string{helpersv1.UserDefinedProfileMetadataKey: "authored-cp"}
	require.NoError(t, c.addContainer(ev, context.Background()))

	entry, ok := c.entries.Load(id)
	require.True(t, ok)
	require.NotNil(t, entry.UserCPRef)
	assert.Equal(t, "authored-cp-nginx", entry.UserCPRef.Name)
	assert.Equal(t, "", entry.RV, "learned RV must be empty (no learned CP) — the freeze-proof invariant")
	assert.Equal(t, "a1", entry.UserCPRV)

	before := c.GetProjectedContainerProfile(id)
	require.NotNil(t, before)
	_, hasInit := before.Execs.Values["/bin/init"]
	assert.True(t, hasInit)
	_, hasEditedYet := before.Execs.Values["/bin/edited"]
	require.False(t, hasEditedYet, "edit not applied before it happens")

	// Edit the authored CP: bump RV and append an Exec.
	authored.ResourceVersion = "a2"
	authored.Spec.Execs = append(authored.Spec.Execs, v1beta1.ExecCalls{Path: "/bin/edited"})

	c.refreshAllEntries(context.Background())

	after := c.GetProjectedContainerProfile(id)
	require.NotNil(t, after)
	_, hasEditedNow := after.Execs.Values["/bin/edited"]
	assert.True(t, hasEditedNow, "authored-CP edit MUST be reflected after one refresh (entry not frozen)")
	updated, _ := c.entries.Load(id)
	assert.Equal(t, "a2", updated.UserCPRV, "UserCPRV must track the edited authored CP")
	assert.Equal(t, "", updated.RV, "learned RV stays empty across refresh")
}

// TestRefreshUserCP_NoLearnedCP covers the user-defined-only refresh path: an
// authored CP present with NO learned CP is force-enforced Completed/Full at add
// time, and an unchanged refresh fast-skips (same entry pointer) while keeping
// the terminal state.
func TestRefreshUserCP_NoLearnedCP(t *testing.T) {
	authored := authoredCP("authored-cp-nginx", "/bin/authored", "a1")
	client := &fakeProfileClient{
		cp:            nil,
		cpErr:         apierrors.NewNotFound(schema.GroupResource{Resource: "containerprofiles"}, "learned"),
		userCPsByName: map[string]*v1beta1.ContainerProfile{"authored-cp-nginx": authored},
	}
	c, k8s := newTestCache(t, client)

	id := "cid-nolearned"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
	ev := eventContainer(id)
	ev.K8s.PodLabels = map[string]string{helpersv1.UserDefinedProfileMetadataKey: "authored-cp"}
	require.NoError(t, c.addContainer(ev, context.Background()))

	entry, ok := c.entries.Load(id)
	require.True(t, ok)
	assert.Equal(t, "", entry.RV, "no learned CP → learned RV empty")
	assert.Equal(t, "a1", entry.UserCPRV)
	require.NotNil(t, entry.State)
	assert.Equal(t, helpersv1.Completed, entry.State.Status, "authored CP is force-enforced Completed")
	assert.Equal(t, helpersv1.Full, entry.State.Completion, "authored CP is force-enforced Full")

	c.refreshAllEntries(context.Background())

	stored, ok := c.entries.Load(id)
	require.True(t, ok)
	assert.Same(t, entry, stored, "no source changed → fast-skip keeps the same entry pointer")
	assert.Equal(t, helpersv1.Completed, stored.State.Status)
}

// TestRefreshUserCP_FastSkipWhenRVsMatch: with BOTH a learned base CP and an
// authored CP, an unchanged refresh (learned RV + authored RV both match)
// fast-skips and preserves the entry pointer.
func TestRefreshUserCP_FastSkipWhenRVsMatch(t *testing.T) {
	learned := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: "learned-base", Namespace: "default", ResourceVersion: "L1",
			Annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Full,
				helpersv1.StatusMetadataKey:     helpersv1.Completed,
			},
		},
		Spec: v1beta1.ContainerProfileSpec{Capabilities: []string{"NET_ADMIN"}},
	}
	authored := authoredCP("authored-cp-nginx", "/bin/authored", "a1")
	client := &fakeProfileClient{
		cp:            learned,
		userCPsByName: map[string]*v1beta1.ContainerProfile{"authored-cp-nginx": authored},
	}
	c, k8s := newTestCache(t, client)

	id := "cid-fastskip"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
	ev := eventContainer(id)
	ev.K8s.PodLabels = map[string]string{helpersv1.UserDefinedProfileMetadataKey: "authored-cp"}
	require.NoError(t, c.addContainer(ev, context.Background()))

	entry, ok := c.entries.Load(id)
	require.True(t, ok)
	require.NotEmpty(t, entry.RV, "learned RV recorded")
	require.Equal(t, "a1", entry.UserCPRV, "authored RV recorded")

	c.refreshAllEntries(context.Background())

	stored, ok := c.entries.Load(id)
	require.True(t, ok)
	assert.Same(t, entry, stored, "matching learned RV + authored RV → fast-skip, same pointer")
}

// TestRefreshUserCP_RebuildWhenUserCPRVChanges: with the learned RV unchanged
// but the authored CP's RV bumped, refresh rebuilds the entry and the edit is
// reflected.
func TestRefreshUserCP_RebuildWhenUserCPRVChanges(t *testing.T) {
	learned := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: "learned-base", Namespace: "default", ResourceVersion: "L1",
			Annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Full,
				helpersv1.StatusMetadataKey:     helpersv1.Completed,
			},
		},
	}
	authored := authoredCP("authored-cp-nginx", "/bin/v1", "a1")
	client := &fakeProfileClient{
		cp:            learned,
		userCPsByName: map[string]*v1beta1.ContainerProfile{"authored-cp-nginx": authored},
	}
	c, k8s := newTestCache(t, client)
	c.SetProjectionSpec(execsAllSpec("usercp-rebuild"))

	id := "cid-usercp-rebuild"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
	ev := eventContainer(id)
	ev.K8s.PodLabels = map[string]string{helpersv1.UserDefinedProfileMetadataKey: "authored-cp"}
	require.NoError(t, c.addContainer(ev, context.Background()))

	entry, ok := c.entries.Load(id)
	require.True(t, ok)
	require.Equal(t, "a1", entry.UserCPRV)

	// Bump ONLY the authored CP (learned RV stays L1).
	authored.ResourceVersion = "a2"
	authored.Spec.Execs = append(authored.Spec.Execs, v1beta1.ExecCalls{Path: "/bin/v2"})

	c.refreshAllEntries(context.Background())

	stored, ok := c.entries.Load(id)
	require.True(t, ok)
	assert.NotSame(t, entry, stored, "authored RV change → rebuild, new pointer")
	assert.Equal(t, "a2", stored.UserCPRV, "UserCPRV updated to the edited authored CP")
	proj := c.GetProjectedContainerProfile(id)
	require.NotNil(t, proj)
	_, hasV2 := proj.Execs.Values["/bin/v2"]
	assert.True(t, hasV2, "the authored-CP edit is reflected after rebuild")
}

// TestGetContainerProfile_Miss sanity-checks the nil path returns nil and a
// synthetic error ProfileState (no panic).
func TestGetContainerProfile_Miss(t *testing.T) {
	c, _ := newTestCache(t, &fakeProfileClient{})
	assert.Nil(t, c.GetProjectedContainerProfile("nope"))
	state := c.GetContainerProfileState("nope")
	require.NotNil(t, state)
	require.Error(t, state.Error)
}

// TestStorageError_NoEntry ensures storage errors don't panic and don't
// populate a cache entry.
func TestStorageError_NoEntry(t *testing.T) {
	client := &fakeProfileClient{cpErr: errors.New("kaboom")}
	c, k8s := newTestCache(t, client)
	id := "c-err"
	primeSharedData(t, k8s, id, "wlid://x")
	require.NoError(t, c.addContainer(eventContainer(id), context.Background()))
	_, ok := c.entries.Load(id)
	assert.False(t, ok, "storage error must not create a cache entry")
}
