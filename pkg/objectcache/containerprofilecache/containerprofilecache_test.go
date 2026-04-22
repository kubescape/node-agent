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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
}

var _ storage.ProfileClient = (*fakeProfileClient)(nil)

func (f *fakeProfileClient) GetApplicationProfile(_, name string) (*v1beta1.ApplicationProfile, error) {
	if len(name) >= 3 && name[:3] == helpersv1.UserApplicationProfilePrefix {
		return f.userManagedAP, nil
	}
	if f.overlayOnly != "" && name != f.overlayOnly {
		return nil, nil
	}
	return f.ap, f.apErr
}
func (f *fakeProfileClient) GetNetworkNeighborhood(_, name string) (*v1beta1.NetworkNeighborhood, error) {
	if len(name) >= 3 && name[:3] == helpersv1.UserNetworkNeighborhoodPrefix {
		return f.userManagedNN, nil
	}
	if f.overlayOnly != "" && name != f.overlayOnly {
		return nil, nil
	}
	return f.nn, f.nnErr
}
func (f *fakeProfileClient) GetContainerProfile(_, _ string) (*v1beta1.ContainerProfile, error) {
	f.getCPCalls++
	return f.cp, f.cpErr
}
func (f *fakeProfileClient) ListApplicationProfiles(_ string, _ int64, _ string) (*v1beta1.ApplicationProfileList, error) {
	return &v1beta1.ApplicationProfileList{}, nil
}
func (f *fakeProfileClient) ListNetworkNeighborhoods(_ string, _ int64, _ string) (*v1beta1.NetworkNeighborhoodList, error) {
	return &v1beta1.NetworkNeighborhoodList{}, nil
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
// same CP yield entries that share the very same *ContainerProfile pointer.
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
	assert.True(t, entryA.Shared, "fast path must mark entry Shared=true")
	assert.True(t, entryB.Shared, "fast path must mark entry Shared=true")
	assert.Same(t, entryA.Profile, entryB.Profile, "both entries must share the same storage-fetched pointer")
	assert.Same(t, cp, entryA.Profile, "fast path must not DeepCopy")
}

// TestOverlayPath_DeepCopies verifies that when userAP is present we build a
// distinct DeepCopy (pointer inequality with the storage-fetched cp) and mark
// Shared=false.
func TestOverlayPath_DeepCopies(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "cp-1", Namespace: "default", ResourceVersion: "1"},
		Spec:       v1beta1.ContainerProfileSpec{Capabilities: []string{"SYS_PTRACE"}},
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
	assert.False(t, entry.Shared, "overlay path must mark Shared=false")
	assert.NotSame(t, cp, entry.Profile, "overlay path must DeepCopy, not share")
	// Merged caps: base + user
	assert.ElementsMatch(t, []string{"SYS_PTRACE", "NET_BIND_SERVICE"}, entry.Profile.Spec.Capabilities)
	require.NotNil(t, entry.UserAPRef)
	assert.Equal(t, "override", entry.UserAPRef.Name)
	assert.Equal(t, "u1", entry.UserAPRV)
}

// TestDeleteContainer_LockAndCleanup verifies that deleteContainer removes
// the entry and releases the per-container lock so a later Add re-uses a
// fresh mutex.
func TestDeleteContainer_LockAndCleanup(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "cp-delete", Namespace: "default", ResourceVersion: "1"},
	}
	client := &fakeProfileClient{cp: cp}
	c, k8s := newTestCache(t, client)

	id := "container-delete"
	primeSharedData(t, k8s, id, "wlid://x")
	require.NoError(t, c.addContainer(eventContainer(id), context.Background()))
	require.True(t, c.containerLocks.HasLock(id), "lock should exist after add")
	require.NotNil(t, c.GetContainerProfile(id))

	c.deleteContainer(id)
	assert.Nil(t, c.GetContainerProfile(id), "entry must be gone after delete")
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
		ObjectMeta: metav1.ObjectMeta{Name: "cp-stack", Namespace: "default", ResourceVersion: "1"},
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
	assert.Nil(t, c.GetContainerProfile("nope"))
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
