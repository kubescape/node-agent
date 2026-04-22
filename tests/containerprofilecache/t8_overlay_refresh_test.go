package containerprofilecache_integration

// TestT8_EndToEndRefreshUpdatesProjection mirrors the same-named unit test from
// reconciler_test.go using only the public / test-helper API so it can live at
// the integration test level (tests/containerprofilecache/).
//
// Scenario: an entry backed by CP (RV=100) + user-AP overlay (RV=50) is seeded
// via SeedEntryWithOverlayForTest. Storage is mutated to serve a new AP
// (RV=51, different execs). A single RefreshAllEntriesForTest call must rebuild
// the projection so the cached execs reflect the new AP, not the stale one.

import (
	"context"
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

func TestT8_EndToEndRefreshUpdatesProjection(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "cp",
			Namespace:       "default",
			ResourceVersion: "100",
		},
		Spec: v1beta1.ContainerProfileSpec{
			Execs: []v1beta1.ExecCalls{{Path: "/bin/base", Args: []string{"a"}}},
		},
	}
	apV1 := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "override",
			Namespace:       "default",
			ResourceVersion: "50",
		},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{{
				Name:  "nginx",
				Execs: []v1beta1.ExecCalls{{Path: "/bin/old", Args: []string{"x"}}},
			}},
		},
	}
	apV2 := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "override",
			Namespace:       "default",
			ResourceVersion: "51",
		},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{{
				Name:  "nginx",
				Execs: []v1beta1.ExecCalls{{Path: "/bin/new", Args: []string{"y"}}},
			}},
		},
	}

	store := newFakeStorage(cp)
	store.mu.Lock()
	store.ap = apV1
	store.mu.Unlock()

	k8s := newFakeK8sCache()
	cfg := config.Config{
		ProfilesCacheRefreshRate: 30 * time.Second,
		StorageRPCBudget:         500 * time.Millisecond,
	}
	cache := cpc.NewContainerProfileCache(cfg, store, k8s, nil)

	const id = "c1"
	// Seed a projected entry with a stale UserAPRV so refresh sees the RV change.
	// The Profile here is just the base CP; the reconciler will re-project on refresh.
	cache.SeedEntryWithOverlayForTest(id, &cpc.CachedContainerProfile{
		Profile:       cp,
		State:         &objectcache.ProfileState{Name: cp.Name},
		ContainerName: "nginx",
		PodName:       "nginx-abc",
		Namespace:     "default",
		PodUID:        "uid-1",
		CPName:        "cp",
		RV:            "100",
		UserAPRV:      "50", // stale — triggers rebuild when storage returns RV=51
		Shared:        false,
	}, "default", "override", "", "")

	// Advance storage to apV2 (RV=51). The reconciler will see the RV mismatch
	// and rebuild the projection from cp + apV2.
	store.mu.Lock()
	store.ap = apV2
	store.mu.Unlock()

	cache.RefreshAllEntriesForTest(context.Background())

	stored := cache.GetContainerProfile(id)
	require.NotNil(t, stored, "entry must remain after refresh")

	var paths []string
	for _, e := range stored.Spec.Execs {
		paths = append(paths, e.Path)
	}
	assert.Contains(t, paths, "/bin/base", "base CP exec must be preserved after overlay refresh")
	assert.Contains(t, paths, "/bin/new", "new user-AP exec must appear in the rebuilt projection")
	assert.NotContains(t, paths, "/bin/old", "stale user-AP exec must NOT survive the rebuild")
}
