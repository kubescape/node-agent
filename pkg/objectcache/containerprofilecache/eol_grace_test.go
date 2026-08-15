package containerprofilecache

import (
	"context"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

// TestProjectedProfile_SurvivesContainerRemovalGrace pins the end-of-life
// contract for the event pipeline: when a container is removed, events that
// were emitted during its life are still in flight (ordered event queue 50ms
// collection tick + batching + worker pool), and the rule engine resolves the
// projected profile by container ID at evaluation time. Deleting the cache
// entry immediately on the remove callback makes rules with
// ProfileDependency=Required (e.g. R0001) silently suppress the container's
// terminal events as "profile_incomplete".
//
// Evidence: CI run 31846699597 Test_48 — init container "setup"
// (sh -c "sleep 75; /usr/bin/id"): remove processed at 22:44:26, terminal exec
// evaluated afterwards, zero R0001 despite adopted profile and 98 R0003 during
// the container's life.
//
// Contract: the projected profile must remain resolvable for a grace window
// after the remove callback (long enough to cover the event pipeline delay),
// and only then be evicted.
func TestProjectedProfile_SurvivesContainerRemovalGrace(t *testing.T) {
	c, _ := newTestCache(t, &fakeProfileClient{})

	c.SeedEntryForTest("eol-c1", &CachedContainerProfile{
		Projected: &objectcache.ProjectedContainerProfile{},
	})
	require.NotNil(t, c.GetProjectedContainerProfile("eol-c1"), "seeded entry must resolve")

	c.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeRemoveContainer,
		Container: eventContainer("eol-c1"),
	})

	// Poll for 300ms: the entry must remain resolvable throughout — this is
	// well inside any reasonable grace window and far beyond the current
	// immediate async delete.
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		require.NotNil(t, c.GetProjectedContainerProfile("eol-c1"),
			"projected profile must remain resolvable during the removal grace window so in-flight events can be evaluated")
		time.Sleep(20 * time.Millisecond)
	}
}

// TestProjectedProfile_EvictedAfterRemovalGrace pins the eviction side: once
// the grace window has elapsed, the entry is deleted (no unbounded growth).
func TestProjectedProfile_EvictedAfterRemovalGrace(t *testing.T) {
	c, _ := newTestCache(t, &fakeProfileClient{})
	c.SetRemovalGraceForTest(50 * time.Millisecond)

	c.SeedEntryForTest("eol-c2", &CachedContainerProfile{
		Projected: &objectcache.ProjectedContainerProfile{},
	})
	c.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeRemoveContainer,
		Container: eventContainer("eol-c2"),
	})

	require.Eventually(t, func() bool {
		return c.GetProjectedContainerProfile("eol-c2") == nil
	}, 2*time.Second, 25*time.Millisecond,
		"entry must be evicted after the removal grace period")
}

// TestReconciler_HonorsRemovalGraceForTerminatedContainer pins the reconciler
// side of the coordination: a Terminated container observed by reconcileOnce
// is NOT evicted on the first observation (grace), only on a later tick after
// the grace has elapsed — and never while a deferred remove-callback deletion
// is pending. Without this, a reconciler tick landing inside the removal
// grace window would reintroduce the end-of-life race it exists to close.
func TestReconciler_HonorsRemovalGraceForTerminatedContainer(t *testing.T) {
	k8s := newControllableK8sCache()
	cfg := config.Config{ProfilesCacheRefreshRate: 30 * time.Second}
	c := NewContainerProfileCache(cfg, &fakeProfileClient{}, k8s, nil)
	c.SetRemovalGraceForTest(100 * time.Millisecond)

	c.SeedEntryForTest("eol-c3", &CachedContainerProfile{
		Projected:     &objectcache.ProjectedContainerProfile{},
		ContainerName: "setup",
		PodName:       "pod-eol",
		Namespace:     "ns-eol",
	})
	// Publish a pod whose container status is Terminated so the reconciler
	// sees a clearly-exited container.
	k8s.setPod("ns-eol", "pod-eol", &corev1.Pod{
		Status: corev1.PodStatus{
			InitContainerStatuses: []corev1.ContainerStatus{{
				Name:        "setup",
				ContainerID: "containerd://eol-c3",
				State:       corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}},
			}},
		},
	})

	// First observation: marked, not evicted.
	c.ReconcileOnce(context.Background())
	require.NotNil(t, c.GetProjectedContainerProfile("eol-c3"),
		"first Terminated observation must not evict (grace)")

	// Second observation inside the grace: still not evicted.
	c.ReconcileOnce(context.Background())
	require.NotNil(t, c.GetProjectedContainerProfile("eol-c3"),
		"Terminated observation inside the grace window must not evict")

	// After the grace: evicted.
	time.Sleep(150 * time.Millisecond)
	c.ReconcileOnce(context.Background())
	require.Nil(t, c.GetProjectedContainerProfile("eol-c3"),
		"Terminated entry must be evicted once the grace has elapsed")
}
