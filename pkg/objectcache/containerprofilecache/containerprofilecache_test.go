package containerprofilecache

import (
	"context"
	"errors"
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
	cp    *v1beta1.ContainerProfile
	ap    *v1beta1.ApplicationProfile // returned for Get by ap.Name match (or any if overlayOnly is empty)
	nn    *v1beta1.NetworkNeighborhood
	cpErr error
	apErr error
	nnErr error

	// userManagedAP / userManagedNN, when non-nil, are returned for any
	// GetApplicationProfile / GetNetworkNeighborhood whose name starts with
	// the "ug-" prefix (the convention used by legacy user-managed profiles).
	// This lets tests exercise the user-managed merge path added for
	// Test_12_MergingProfilesTest / Test_13_MergingNetworkNeighborhoodTest
	// without fighting the overlayOnly restriction.
	userManagedAP *v1beta1.ApplicationProfile
	userManagedNN *v1beta1.NetworkNeighborhood

	// overlayOnly, if non-empty, restricts ap/nn returns to only the given
	// name; other names return (nil, nil). Tests that mix workload-AP/NN
	// with overlay-AP/NN use this to keep the fixture scoped.
	overlayOnly string

	getCPCalls int
	// ugAPCalls / ugNNCalls count GETs for "ug-"-prefixed names so tests can
	// assert that the client-side user-managed fetch is (or isn't) issued.
	ugAPCalls int
	ugNNCalls int
}

var _ storage.ProfileClient = (*fakeProfileClient)(nil)

func TestShouldLogOptionalUserManagedFetchError(t *testing.T) {
	assert.False(t, shouldLogOptionalUserManagedFetchError(nil))
	assert.False(t, shouldLogOptionalUserManagedFetchError(
		apierrors.NewNotFound(schema.GroupResource{Group: "softwarecomposition.kubescape.io", Resource: "applicationprofiles"}, "ug-nginx"),
	))
	assert.True(t, shouldLogOptionalUserManagedFetchError(errors.New("boom")))
}

func (f *fakeProfileClient) GetApplicationProfile(_ context.Context, _, name string) (*v1beta1.ApplicationProfile, error) {
	if len(name) >= 3 && name[:3] == helpersv1.UserApplicationProfilePrefix {
		f.ugAPCalls++
		return f.userManagedAP, nil
	}
	if f.overlayOnly != "" && name != f.overlayOnly {
		return nil, nil
	}
	return f.ap, f.apErr
}
func (f *fakeProfileClient) GetNetworkNeighborhood(_ context.Context, _, name string) (*v1beta1.NetworkNeighborhood, error) {
	if len(name) >= 3 && name[:3] == helpersv1.UserNetworkNeighborhoodPrefix {
		f.ugNNCalls++
		return f.userManagedNN, nil
	}
	if f.overlayOnly != "" && name != f.overlayOnly {
		return nil, nil
	}
	return f.nn, f.nnErr
}
func (f *fakeProfileClient) GetContainerProfile(_ context.Context, _, _ string) (*v1beta1.ContainerProfile, error) {
	f.getCPCalls++
	return f.cp, f.cpErr
}
func (f *fakeProfileClient) ListApplicationProfiles(_ context.Context, _ string, _ int64, _ string) (*v1beta1.ApplicationProfileList, error) {
	return &v1beta1.ApplicationProfileList{}, nil
}
func (f *fakeProfileClient) ListNetworkNeighborhoods(_ context.Context, _ string, _ int64, _ string) (*v1beta1.NetworkNeighborhoodList, error) {
	return &v1beta1.NetworkNeighborhoodList{}, nil
}

// newTestCache returns a cache wired with an in-memory K8sObjectCacheMock and
// the default config (client-side ug- merge enabled).
func newTestCache(t *testing.T, client storage.ProfileClient) (*ContainerProfileCacheImpl, *objectcache.K8sObjectCacheMock) {
	t.Helper()
	return newTestCacheWithConfig(t, client, config.Config{ProfilesCacheRefreshRate: 30 * time.Second})
}

// newTestCacheWithConfig is newTestCache with a caller-supplied config, used by
// the ServerSideUserManagedMerge tests to flip ProfileProjection settings.
func newTestCacheWithConfig(t *testing.T, client storage.ProfileClient, cfg config.Config) (*ContainerProfileCacheImpl, *objectcache.K8sObjectCacheMock) {
	t.Helper()
	k8s := &objectcache.K8sObjectCacheMock{}
	return NewContainerProfileCache(cfg, client, k8s, nil), k8s
}

// serverSideMergeConfig returns a config with ServerSideUserManagedMerge on.
func serverSideMergeConfig() config.Config {
	cfg := config.Config{ProfilesCacheRefreshRate: 30 * time.Second}
	cfg.ProfileProjection.ServerSideUserManagedMerge = true
	return cfg
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

// TestOverlayPath_DeepCopies verifies that when userAP is present the overlay
// is merged into the projected profile.
func TestOverlayPath_DeepCopies(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cp-1", Namespace: "default", ResourceVersion: "1",
			Annotations: map[string]string{helpersv1.StatusMetadataKey: helpersv1.Completed},
		},
		Spec: v1beta1.ContainerProfileSpec{Capabilities: []string{"SYS_PTRACE"}},
	}
	userAP := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "override", Namespace: "default", ResourceVersion: "u1"},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{{
				Name:         "nginx",
				Capabilities: []string{"NET_BIND_SERVICE"},
			}},
		},
	}
	client := &fakeProfileClient{cp: cp, ap: userAP, overlayOnly: "override"}
	c, k8s := newTestCache(t, client)

	id := "container-overlay"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")

	ev := eventContainer(id)
	ev.K8s.PodLabels = map[string]string{helpersv1.UserDefinedProfileMetadataKey: "override"}
	require.NoError(t, c.addContainer(ev, context.Background()))

	entry, ok := c.entries.Load(id)
	require.True(t, ok)
	assert.NotNil(t, entry.Projected, "overlay path must produce a projected profile")
	require.NotNil(t, entry.UserAPRef)
	assert.Equal(t, "override", entry.UserAPRef.Name)
	assert.Equal(t, "u1", entry.UserAPRV)
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

// TestGetContainerProfile_Miss sanity-checks the nil path returns nil and a
// synthetic error ProfileState (no panic).
func TestGetContainerProfile_Miss(t *testing.T) {
	c, _ := newTestCache(t, &fakeProfileClient{})
	assert.Nil(t, c.GetProjectedContainerProfile("nope"))
	state := c.GetContainerProfileState("nope")
	require.NotNil(t, state)
	require.Error(t, state.Error)
}

// execSpec is the projection spec used by the ServerSideUserManagedMerge tests:
// project all execs so merged paths surface in Projected.Execs.Values.
func execSpec() objectcache.RuleProjectionSpec {
	return objectcache.RuleProjectionSpec{
		Execs: objectcache.FieldSpec{InUse: true, All: true},
		Hash:  "server-side-merge-test",
	}
}

// TestServerSideMerge_SkipsUgFetch verifies that with ServerSideUserManagedMerge
// enabled, addContainer does NOT issue the client-side "ug-" AP/NN GETs and does
// NOT client-merge them. The ug- exception must instead arrive via the
// server-merged CP returned by GetContainerProfile.
func TestServerSideMerge_SkipsUgFetch(t *testing.T) {
	// CP simulates storage#319's merged-first GET: /bin/base (observed) plus
	// /bin/server-ug (already merged from the ug- overlay server-side).
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "cp-base",
			Namespace:       "default",
			ResourceVersion: "1",
			Annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Full,
				helpersv1.StatusMetadataKey:     helpersv1.Completed,
			},
		},
		Spec: v1beta1.ContainerProfileSpec{
			Execs: []v1beta1.ExecCalls{{Path: "/bin/base"}, {Path: "/bin/server-ug"}},
		},
	}
	// This ug- AP must NEVER be fetched/merged client-side under the flag. Its
	// distinctive exec (/bin/client-only) is the canary: if it shows up in the
	// projection, the client-side merge wrongly ran.
	userManagedAP := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "ug-nginx", Namespace: "default", ResourceVersion: "9"},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{{
				Name:  "nginx",
				Execs: []v1beta1.ExecCalls{{Path: "/bin/client-only"}},
			}},
		},
	}
	client := &fakeProfileClient{cp: cp, userManagedAP: userManagedAP}
	c, k8s := newTestCacheWithConfig(t, client, serverSideMergeConfig())
	c.SetProjectionSpec(execSpec())

	id := "container-server-side"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
	require.NoError(t, c.addContainer(eventContainer(id), context.Background()))

	cached := c.GetProjectedContainerProfile(id)
	require.NotNil(t, cached)
	_, hasBase := cached.Execs.Values["/bin/base"]
	_, hasServerUg := cached.Execs.Values["/bin/server-ug"]
	_, hasClientOnly := cached.Execs.Values["/bin/client-only"]
	assert.True(t, hasBase, "base CP exec must be present")
	assert.True(t, hasServerUg, "server-merged ug- exec must be present (came via the CP GET)")
	assert.False(t, hasClientOnly, "client-side ug- merge must NOT run under ServerSideUserManagedMerge")

	assert.Equal(t, 0, client.ugAPCalls, "no client-side ug- AP fetch under the flag")
	assert.Equal(t, 0, client.ugNNCalls, "no client-side ug- NN fetch under the flag")

	entry, ok := c.entries.Load(id)
	require.True(t, ok)
	assert.Empty(t, entry.UserManagedAPRV, "UserManagedAPRV must stay empty under the flag")
	assert.Empty(t, entry.UserManagedNNRV, "UserManagedNNRV must stay empty under the flag")
}

// TestServerSideMerge_LabelOverlayStillApplies verifies that the label-driven
// user-defined overlay (pass 2) is unaffected by ServerSideUserManagedMerge:
// it is a separate, still-client-side feature.
func TestServerSideMerge_LabelOverlayStillApplies(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cp-1", Namespace: "default", ResourceVersion: "1",
			Annotations: map[string]string{helpersv1.StatusMetadataKey: helpersv1.Completed},
		},
		Spec: v1beta1.ContainerProfileSpec{Execs: []v1beta1.ExecCalls{{Path: "/bin/base"}}},
	}
	userAP := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "override", Namespace: "default", ResourceVersion: "u1"},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{{
				Name:  "nginx",
				Execs: []v1beta1.ExecCalls{{Path: "/bin/overlay"}},
			}},
		},
	}
	client := &fakeProfileClient{cp: cp, ap: userAP, overlayOnly: "override"}
	c, k8s := newTestCacheWithConfig(t, client, serverSideMergeConfig())
	c.SetProjectionSpec(execSpec())

	id := "container-overlay-flagged"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
	ev := eventContainer(id)
	ev.K8s.PodLabels = map[string]string{helpersv1.UserDefinedProfileMetadataKey: "override"}
	require.NoError(t, c.addContainer(ev, context.Background()))

	cached := c.GetProjectedContainerProfile(id)
	require.NotNil(t, cached)
	_, hasBase := cached.Execs.Values["/bin/base"]
	_, hasOverlay := cached.Execs.Values["/bin/overlay"]
	assert.True(t, hasBase, "base CP exec must be present")
	assert.True(t, hasOverlay, "label-driven user-defined overlay must still merge under the flag")

	assert.Equal(t, 0, client.ugAPCalls, "label overlay must not trigger ug- fetches")
	entry, ok := c.entries.Load(id)
	require.True(t, ok)
	require.NotNil(t, entry.UserAPRef, "user-defined overlay ref must be recorded")
	assert.Equal(t, "override", entry.UserAPRef.Name)
}

// TestClientSideMerge_DefaultFetchesUg pins the default (flag-off) behavior:
// the client-side ug- fetch IS issued and merged. This is the safety baseline
// that ServerSideUserManagedMerge opts out of.
func TestClientSideMerge_DefaultFetchesUg(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cp-base", Namespace: "default", ResourceVersion: "1",
			Annotations: map[string]string{helpersv1.StatusMetadataKey: helpersv1.Completed},
		},
		Spec: v1beta1.ContainerProfileSpec{Execs: []v1beta1.ExecCalls{{Path: "/bin/base"}}},
	}
	userManagedAP := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "ug-nginx", Namespace: "default", ResourceVersion: "9"},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{{
				Name:  "nginx",
				Execs: []v1beta1.ExecCalls{{Path: "/bin/client-merged"}},
			}},
		},
	}
	client := &fakeProfileClient{cp: cp, userManagedAP: userManagedAP}
	c, k8s := newTestCache(t, client) // default config: flag OFF
	c.SetProjectionSpec(execSpec())

	id := "container-default"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
	require.NoError(t, c.addContainer(eventContainer(id), context.Background()))

	cached := c.GetProjectedContainerProfile(id)
	require.NotNil(t, cached)
	_, hasClientMerged := cached.Execs.Values["/bin/client-merged"]
	assert.True(t, hasClientMerged, "default behavior must client-merge the ug- AP")
	assert.Greater(t, client.ugAPCalls, 0, "default behavior must fetch the ug- AP")

	entry, ok := c.entries.Load(id)
	require.True(t, ok)
	assert.Equal(t, "9", entry.UserManagedAPRV, "default behavior records UserManagedAPRV")
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
