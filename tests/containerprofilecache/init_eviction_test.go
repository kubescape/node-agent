package containerprofilecache_integration

import (
	"context"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	cpc "github.com/kubescape/node-agent/pkg/objectcache/containerprofilecache"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// newCPCForEvictionTest wires up a ContainerProfileCacheImpl with the provided
// storage and k8s stubs for eviction testing. Start is NOT called so the
// reconciler goroutine never runs — tests drive ReconcileOnce directly.
func newCPCForEvictionTest(storage *stubStorage, k8s *stubK8sCache) *cpc.ContainerProfileCacheImpl {
	cfg := config.Config{ProfilesCacheRefreshRate: 30 * time.Second}
	return cpc.NewContainerProfileCache(cfg, storage, k8s, nil)
}

// seedEntry builds and seeds a minimal CachedContainerProfile into the cache
// using the exported SeedEntryForTest hook.
func seedEntry(cache *cpc.ContainerProfileCacheImpl, containerID string, cp *v1beta1.ContainerProfile, containerName, podName, namespace, podUID string) {
	entry := &cpc.CachedContainerProfile{
		Profile:       cp,
		State:         &objectcache.ProfileState{Name: cp.Name},
		ContainerName: containerName,
		PodName:       podName,
		Namespace:     namespace,
		PodUID:        podUID,
		CPName:        cp.Name,
		RV:            cp.ResourceVersion,
		Shared:        true,
	}
	cache.SeedEntryForTest(containerID, entry)
}

// TestInitContainerEvictionViaRemoveEvent — T2a.
//
// Pod has 1 init container (initID) + 1 regular container (regID), both seeded
// into the cache. Fire EventTypeRemoveContainer for the init container via
// ContainerCallback. Assert that the init entry is evicted and the regular
// entry is untouched.
func TestInitContainerEvictionViaRemoveEvent(t *testing.T) {
	const (
		namespace   = "default"
		podName     = "testpod"
		initID      = "init-container-id"
		regID       = "regular-container-id"
		initName    = "init-container"
		regularName = "regular"
		podUID      = "pod-uid-t2a"
	)

	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "cp-test",
			Namespace:       namespace,
			ResourceVersion: "1",
		},
	}
	store := newFakeStorage(cp)
	k8s := newFakeK8sCache()
	cache := newCPCForEvictionTest(store, k8s)

	// Seed both containers directly — no goroutines, no races.
	seedEntry(cache, initID, cp, initName, podName, namespace, podUID)
	seedEntry(cache, regID, cp, regularName, podName, namespace, podUID)

	assert.NotNil(t, cache.GetContainerProfile(initID), "init container must be cached before eviction")
	assert.NotNil(t, cache.GetContainerProfile(regID), "regular container must be cached before eviction")

	// Fire remove event for init container only. deleteContainer runs in a
	// goroutine; wait for it to complete.
	cache.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeRemoveContainer,
		Container: makeTestContainer(initID, podName, namespace, initName),
	})

	// deleteContainer goroutine is very fast (just a map delete + lock release).
	assert.Eventually(t, func() bool {
		return cache.GetContainerProfile(initID) == nil
	}, 3*time.Second, 10*time.Millisecond, "init container entry must be evicted after RemoveContainer event")

	// Regular container must survive.
	assert.NotNil(t, cache.GetContainerProfile(regID), "regular container entry must remain after init eviction")
}

// TestMissedRemoveEventEvictedByReconciler — T2b.
//
// Init container entry is seeded directly. Pod status is then flipped so the
// init container is no longer Running (simulating it finishing without a remove
// event). ReconcileOnce must evict the stale entry.
func TestMissedRemoveEventEvictedByReconciler(t *testing.T) {
	const (
		namespace = "default"
		podName   = "testpod-reconcile"
		initID    = "init-container-reconcile"
		initName  = "init-container"
		podUID    = "pod-uid-reconcile"
	)

	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "cp-reconcile",
			Namespace:       namespace,
			ResourceVersion: "1",
		},
	}
	store := newFakeStorage(cp)
	k8s := newFakeK8sCache()

	// Start: pod shows init container Running.
	runningPod := makeTestPod(podName, namespace, podUID,
		nil,
		[]corev1.ContainerStatus{{
			Name:        initName,
			ContainerID: "containerd://" + initID,
			State:       corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
		}},
	)
	k8s.setPod(namespace, podName, runningPod)

	cache := newCPCForEvictionTest(store, k8s)

	// Seed init container entry directly.
	seedEntry(cache, initID, cp, initName, podName, namespace, podUID)
	assert.NotNil(t, cache.GetContainerProfile(initID), "init container must be seeded before reconciler test")

	// Simulate init container finishing: flip status to Terminated, no remove event.
	terminatedPod := makeTestPod(podName, namespace, podUID,
		nil,
		[]corev1.ContainerStatus{{
			Name:        initName,
			ContainerID: "containerd://" + initID,
			State: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{ExitCode: 0},
			},
		}},
	)
	k8s.setPod(namespace, podName, terminatedPod)

	// Drive the reconciler directly — no tick loop running, no goroutines.
	cache.ReconcileOnce(context.Background())

	assert.Nil(t, cache.GetContainerProfile(initID),
		"reconciler must evict init container entry when pod status shows Terminated")
}
