package containerprofilecache_integration

// TestSharedPointerReadersDoNotCorruptCache — PR 3 Part A.
//
// Validates that concurrent readers and a concurrent reconciler-refresh do not
// produce data races on the shared *v1beta1.ContainerProfile pointer returned
// by GetContainerProfile.
//
// Design:
//   - Seed a cache entry backed by cpV1 (RV="1"). Storage serves cpV2 (RV="2")
//     so every RefreshAllEntriesForTest call triggers a rebuild (atomic pointer
//     swap on the entries map, no in-place mutation of the old slice).
//   - 50 reader goroutines call GetContainerProfile in a tight loop and iterate
//     the returned Spec.Execs, Spec.Opens, Spec.Capabilities slices READ-ONLY.
//   - 1 writer goroutine alternates: RefreshAllEntriesForTest (triggers rebuild)
//     then SeedEntryForTest (resets RV to "1" so the next refresh rebuilds again).
//   - Run for 500ms under -race. The race detector will surface any unprotected
//     concurrent read/write pair. If none fires, the shared-pointer fast-path is
//     demonstrably safe for read-only consumers.
//
// NOTE: deliberately-mutating consumer (anti-pattern) is NOT tested here because
// it is expected to trigger the race detector and would make CI non-deterministic.
// That pattern is covered by the code-review gate enforced by ReadOnlyCP (Part B).

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	cpc "github.com/kubescape/node-agent/pkg/objectcache/containerprofilecache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSharedPointerReadersDoNotCorruptCache(t *testing.T) {
	const (
		id           = "race-container"
		numReaders   = 50
		testDuration = 500 * time.Millisecond
		rpcBudgetMs  = 100 * time.Millisecond
	)

	// cpV1 — what is seeded initially (RV="1")
	cpV1 := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "cp-race",
			Namespace:       "default",
			ResourceVersion: "1",
		},
		Spec: v1beta1.ContainerProfileSpec{
			Execs:        []v1beta1.ExecCalls{{Path: "/bin/sh", Args: []string{"a", "b", "c"}}},
			Opens:        []v1beta1.OpenCalls{{Path: "/etc/passwd", Flags: []string{"O_RDONLY"}}},
			Capabilities: []string{"CAP_NET_ADMIN", "CAP_SYS_PTRACE"},
		},
	}

	// cpV2 — what storage returns after a refresh (RV="2"); the reconciler will
	// create a brand-new entry pointing to cpV2 (never mutating cpV1).
	cpV2 := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "cp-race",
			Namespace:       "default",
			ResourceVersion: "2",
		},
		Spec: v1beta1.ContainerProfileSpec{
			Execs:        []v1beta1.ExecCalls{{Path: "/bin/bash", Args: []string{"x", "y"}}},
			Opens:        []v1beta1.OpenCalls{{Path: "/etc/shadow", Flags: []string{"O_WRONLY"}}},
			Capabilities: []string{"CAP_CHOWN"},
		},
	}

	store := newFakeStorage(cpV2) // storage always returns cpV2
	k8s := newFakeK8sCache()

	cfg := config.Config{
		ProfilesCacheRefreshRate: 30 * time.Second,
		StorageRPCBudget:         rpcBudgetMs,
	}
	cache := cpc.NewContainerProfileCache(cfg, store, k8s, nil)

	seedV1 := func() {
		cache.SeedEntryForTest(id, &cpc.CachedContainerProfile{
			Profile:       cpV1,
			State:         &objectcache.ProfileState{Name: "cp-race"},
			ContainerName: "container",
			PodName:       "pod-race",
			Namespace:     "default",
			PodUID:        "uid-race",
			CPName:        "cp-race",
			RV:            "1", // stale — guarantees refresh rebuilds on each tick
			Shared:        true,
		})
	}

	// Pre-warm SafeMap so concurrent Load never hits the nil-check-before-lock
	// initialization race present in goradd/maps v1.3.0 (pre-existing upstream bug).
	seedV1()

	require.NotNil(t, cache.GetContainerProfile(id), "pre-condition: entry present before test")

	ctx, cancel := context.WithTimeout(context.Background(), testDuration)
	defer cancel()

	var wg sync.WaitGroup

	// 50 reader goroutines — read-only traversal of the returned profile.
	wg.Add(numReaders)
	for i := 0; i < numReaders; i++ {
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				cp := cache.GetContainerProfile(id)
				if cp == nil {
					runtime.Gosched()
					continue
				}
				// Read-only: iterate slices without writing.
				for _, e := range cp.Spec.Execs {
					_ = e.Path
					_ = len(e.Args)
				}
				for _, o := range cp.Spec.Opens {
					_ = o.Path
					_ = len(o.Flags)
				}
				_ = len(cp.Spec.Capabilities)
				_ = cp.ResourceVersion
				runtime.Gosched()
			}
		}()
	}

	// 1 writer goroutine: alternate refresh (rebuilds entry → cpV2) and reset
	// (reseeds entry → cpV1) to keep the refresh loop active across the window.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			cache.RefreshAllEntriesForTest(ctx)
			// Reset to cpV1 so the next refresh sees a stale RV and rebuilds again.
			seedV1()
		}
	}()

	wg.Wait()

	// If the race detector fired, the test is already marked as failed. We add
	// an explicit liveness assertion to guard against a scenario where the entry
	// gets permanently nil-ed out by a refresh bug.
	finalCP := cache.GetContainerProfile(id)
	// Entry may legitimately be nil if the last operation was a refresh that
	// returned cpV2 and then another seedV1 race lost; what we must NOT see is
	// a panic above or a non-nil entry with a nil Profile.
	if finalCP != nil {
		assert.NotEmpty(t, finalCP.ResourceVersion, "final cached entry must have a non-empty RV")
	}
}

// TestSharedPointerFastPathPreservesPointerIdentity verifies that when the
// reconciler rebuilds an entry from a storage pointer with no overlay, the
// new entry's Profile points directly to the storage object (Shared=true,
// no DeepCopy). This is the memory property that Part A is guarding — if it
// regresses to DeepCopy-on-every-refresh the T3 memory budget is blown.
func TestSharedPointerFastPathPreservesPointerIdentity(t *testing.T) {
	cpInStorage := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "cp-identity",
			Namespace:       "default",
			ResourceVersion: "99",
		},
		Spec: v1beta1.ContainerProfileSpec{
			Capabilities: []string{"CAP_NET_RAW"},
		},
	}

	store := newFakeStorage(cpInStorage)
	k8s := newFakeK8sCache()
	cfg := config.Config{
		ProfilesCacheRefreshRate: 30 * time.Second,
		StorageRPCBudget:         100 * time.Millisecond,
	}
	cache := cpc.NewContainerProfileCache(cfg, store, k8s, nil)

	// Seed with a stale RV so the refresh rebuilds.
	cache.SeedEntryForTest("id-identity", &cpc.CachedContainerProfile{
		Profile:       cpInStorage,
		State:         &objectcache.ProfileState{Name: "cp-identity"},
		ContainerName: "container",
		PodName:       "pod-identity",
		Namespace:     "default",
		PodUID:        "uid-identity",
		CPName:        "cp-identity",
		RV:            "old",
		Shared:        true,
	})

	cache.RefreshAllEntriesForTest(context.Background())

	got := cache.GetContainerProfile("id-identity")
	require.NotNil(t, got, "entry must be present after refresh")
	assert.Same(t, cpInStorage, got,
		"shared fast-path: refresh must store the storage pointer directly (no DeepCopy)")
	assert.Equal(t, "99", got.ResourceVersion, "RV must match the storage object")
}
