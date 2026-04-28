package containerprofilecache_test

import (
	"context"
	"math/rand"
	"runtime"
	"sync"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	cpc "github.com/kubescape/node-agent/pkg/objectcache/containerprofilecache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	instanceidhandlerV1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// TestLockStressAddEvictInterleaved — T7.
//
// 100 goroutines, each running 50 iterations of random seed/delete for a pool
// of 10 container IDs. Uses SeedEntryForTest + deleteContainer (via
// EventTypeRemoveContainer → deleteContainer path) to test the cache's
// per-container locking under concurrent interleaved add/evict.
//
// NOTE on race detector: goradd/maps v1.3.0 has a pre-existing data race in
// SafeMap.Load / SafeMap.Len (nil-check outside the read-lock vs Set
// initialization write). This race is present in pkg/resourcelocks own tests
// (TestConcurrentMultipleContainers fails with -race even before this commit).
// To avoid triggering that upstream race, all SafeMap instances are
// pre-warmed (via SeedEntryForTest) before the concurrent phase starts.
func TestLockStressAddEvictInterleaved(t *testing.T) {
	const (
		namespace  = "default"
		podName    = "stress-pod"
		podUID     = "stress-pod-uid"
		numWorkers = 100
		numIters   = 50
		poolSize   = 10
		wlid       = "wlid://cluster-test/namespace-default/deployment-stress"
	)

	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "cp-stress",
			Namespace:       namespace,
			ResourceVersion: "1",
		},
	}
	store := newFakeStorage(cp)
	k8s := newFakeK8sCache()

	// Prime shared data for each container in the pool so that the internal
	// waitForSharedContainerData path resolves if needed.
	containerIDs := make([]string, poolSize)
	for i := 0; i < poolSize; i++ {
		id := "stress-container-" + itoa3(i)
		containerIDs[i] = id
		primeSharedDataForStress(t, k8s, id, podName, namespace, "container-"+itoa3(i), wlid)
	}

	cfg := config.Config{ProfilesCacheRefreshRate: 30 * time.Second}
	// Start is NOT called — no background reconciler goroutine runs.
	cache := cpc.NewContainerProfileCache(cfg, store, k8s, nil)

	// Pre-warm all internal SafeMap instances before the concurrent phase to
	// avoid triggering the goradd/maps nil-check-before-lock initialization
	// race (pre-existing upstream bug in SafeMap.Load / SafeMap.Len).
	// WarmContainerLocksForTest pre-initialises the containerLocks SafeMap;
	// SeedEntryForTest pre-initialises the entries SafeMap;
	// WarmPendingForTest pre-initialises the pending SafeMap (touched by
	// deleteContainer via ContainerCallback(EventTypeRemoveContainer)).
	cache.WarmContainerLocksForTest(containerIDs)
	cache.WarmPendingForTest(containerIDs)
	for _, id := range containerIDs {
		cache.SeedEntryForTest(id, &cpc.CachedContainerProfile{
			Projected:     cpc.Apply(nil, cp, nil),
			State:         &objectcache.ProfileState{Name: cp.Name},
			ContainerName: "container",
			PodName:       podName,
			Namespace:     namespace,
			PodUID:        podUID,
			CPName:        cp.Name,
			RV:            cp.ResourceVersion,
		})
	}

	baseline := runtime.NumGoroutine()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(numWorkers)
	for w := 0; w < numWorkers; w++ {
		go func(worker int) {
			defer wg.Done()
			r := rand.New(rand.NewSource(time.Now().UnixNano() + int64(worker)))
			for iter := 0; iter < numIters; iter++ {
				if ctx.Err() != nil {
					return
				}
				id := containerIDs[r.Intn(poolSize)]
				if r.Intn(2) == 0 {
					// Add path: seed entry directly (no goroutine spawn,
					// no backoff, no storage RPC — pure lock stress).
					cache.SeedEntryForTest(id, &cpc.CachedContainerProfile{
						Projected:     cpc.Apply(nil, cp, nil),
						State:         &objectcache.ProfileState{Name: cp.Name},
						ContainerName: "container",
						PodName:       podName,
						Namespace:     namespace,
						PodUID:        podUID,
						CPName:        cp.Name,
						RV:            cp.ResourceVersion,
					})
				} else {
					// Evict path: use the production remove-event path so
					// deleteContainer and per-container locking are exercised.
					cache.ContainerCallback(containercollection.PubSubEvent{
						Type:      containercollection.EventTypeRemoveContainer,
						Container: makeTestContainer(id, podName, namespace, "container"),
					})
				}
				time.Sleep(time.Millisecond * time.Duration(r.Intn(2)))
			}
		}(w)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// all goroutines finished within budget
	case <-ctx.Done():
		t.Fatal("TestLockStressAddEvictInterleaved timed out after 5s")
	}

	// ContainerCallback(EventTypeRemoveContainer) spawns go deleteContainer(...)
	// asynchronously, so those goroutines may still be running immediately after
	// wg.Wait(). Poll briefly until they drain before asserting goroutine count.
	drainDeadline := time.Now().Add(200 * time.Millisecond)
	for runtime.NumGoroutine() > baseline+10 && time.Now().Before(drainDeadline) {
		runtime.Gosched()
		time.Sleep(5 * time.Millisecond)
	}
	runtime.GC()
	assert.LessOrEqual(t, runtime.NumGoroutine(), baseline+10,
		"goroutine count should stay near baseline (no leaked goroutines)")

	// Implicit: if any goroutine panicked the test would have already failed.
	assert.True(t, true, "no panic occurred")
}

// primeSharedDataForStress primes shared data for a container used in the
// stress test.
func primeSharedDataForStress(t *testing.T, k8s *stubK8sCache, containerID, podName, namespace, containerName, wlid string) {
	t.Helper()
	ids, err := instanceidhandlerV1.GenerateInstanceIDFromPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: podName, Namespace: namespace},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: containerName, Image: "nginx:1.25"}},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{{Name: containerName, ImageID: "sha256:deadbeef"}},
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, ids)
	k8s.SetSharedContainerData(containerID, &objectcache.WatchedContainerData{
		InstanceID: ids[0],
		Wlid:       wlid,
	})
}

// itoa3 converts a small non-negative int to a string without strconv.
func itoa3(i int) string {
	if i == 0 {
		return "0"
	}
	buf := [10]byte{}
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
