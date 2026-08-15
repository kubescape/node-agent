package containerprofilecache

import (
	"context"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// newEphemeralTestCache wires a cache with a scriptable pod source and a short
// removal grace so mark-and-sweep transitions are testable without long sleeps.
func newEphemeralTestCache(t *testing.T) (*ContainerProfileCacheImpl, *controllableK8sCache) {
	t.Helper()
	k8s := newControllableK8sCache()
	cfg := config.Config{ProfilesCacheRefreshRate: 30 * time.Second}
	c := NewContainerProfileCache(cfg, &fakeProfileClient{}, k8s, nil)
	c.SetRemovalGraceForTest(50 * time.Millisecond)
	return c, k8s
}

func seedNamedEntry(c *ContainerProfileCacheImpl, id, containerName, podName, namespace, podUID string) {
	c.SeedEntryForTest(id, &CachedContainerProfile{
		Projected:     &objectcache.ProjectedContainerProfile{},
		ContainerName: containerName,
		PodName:       podName,
		Namespace:     namespace,
		PodUID:        podUID,
	})
}

// podWithEphemeralSpecNoStatus models the observed live-cluster state seconds
// after an ephemeral container is attached: the pod SPEC already declares the
// ephemeral container, the pod STATUS carries containerStatuses and
// initContainerStatuses, but kubelet has not yet published an
// ephemeralContainerStatuses entry for it.
func podWithEphemeralSpecNoStatus(namespace, podName, podUID, ephemeralName string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: podName, Namespace: namespace, UID: types.UID(podUID)},
		Spec: corev1.PodSpec{
			Containers:     []corev1.Container{{Name: "app"}},
			InitContainers: []corev1.Container{{Name: "setup"}},
			EphemeralContainers: []corev1.EphemeralContainer{{
				EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: ephemeralName},
			}},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:        "app",
				ContainerID: "containerd://app-id",
				State:       corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			}},
			InitContainerStatuses: []corev1.ContainerStatus{{
				Name:        "setup",
				ContainerID: "containerd://setup-id",
				State:       corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}},
			}},
		},
	}
}

// TestReconciler_KeepsEphemeralContainerAwaitingStatus pins the ephemeral
// total-loss bug of issue #79: a just-attached ephemeral container is absent
// from every published status list (kubelet lags ephemeralContainerStatuses
// by seconds), and the reconciler classified "statuses published but container
// absent" as reaped — evicting the freshly-adopted profile entry. Nothing
// re-adds it, so every ProfileDependency=Required rule is suppressed for the
// container's entire life (zero alerts of ANY class).
//
// Evidence (live rig): adoption at +1s after attach, reconciler tick 3s later
// with entries_before=2 entries_after=1, zero alerts for the ephemeral
// container over its whole 75s life while the same pod alerted for setup/app.
//
// Contract: a container that is still DECLARED IN THE POD SPEC but has no
// published status yet is NOT reaped — the entry must survive, through
// arbitrarily many ticks and past any grace window.
func TestReconciler_KeepsEphemeralContainerAwaitingStatus(t *testing.T) {
	c, k8s := newEphemeralTestCache(t)

	seedNamedEntry(c, "debug-id", "debug", "pod-eph", "ns-eph", "uid-eph")
	k8s.setPod("ns-eph", "pod-eph", podWithEphemeralSpecNoStatus("ns-eph", "pod-eph", "uid-eph", "debug"))

	// Two ticks separated by more than the removal grace: with the reaped
	// misclassification the second tick evicts; the contract is that the
	// entry survives because the spec still declares the container.
	c.reconcileOnce(context.Background())
	require.NotNil(t, c.GetProjectedContainerProfile("debug-id"),
		"entry must survive the first tick while the ephemeral container awaits its status")

	time.Sleep(80 * time.Millisecond)
	c.reconcileOnce(context.Background())
	require.NotNil(t, c.GetProjectedContainerProfile("debug-id"),
		"entry must survive past the grace window while the container is still declared in the pod spec")
}

// TestReconciler_KeepsInitContainerAwaitingStatusWithEmptyPodUID pins the
// init-container variant: an entry created before the pod appeared in the k8s
// cache can carry an empty PodUID; while the init container's status still has
// an empty ContainerID, the (Name, PodUID) fallback matches nothing and the
// same "absent = reaped" branch evicted the entry. Spec declaration must keep
// it alive.
func TestReconciler_KeepsInitContainerAwaitingStatusWithEmptyPodUID(t *testing.T) {
	c, k8s := newEphemeralTestCache(t)

	// PodUID unknown at entry-creation time.
	seedNamedEntry(c, "init-id", "setup", "pod-init", "ns-init", "")
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-init", Namespace: "ns-init", UID: types.UID("uid-init")},
		Spec: corev1.PodSpec{
			Containers:     []corev1.Container{{Name: "app"}},
			InitContainers: []corev1.Container{{Name: "setup"}},
		},
		Status: corev1.PodStatus{
			// kubelet published the app status but the init container's status
			// carries no ContainerID yet.
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:        "app",
				ContainerID: "containerd://app-id2",
				State:       corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{}},
			}},
		},
	}
	k8s.setPod("ns-init", "pod-init", pod)

	c.reconcileOnce(context.Background())
	time.Sleep(80 * time.Millisecond)
	c.reconcileOnce(context.Background())
	require.NotNil(t, c.GetProjectedContainerProfile("init-id"),
		"init container entry must survive while its name is declared in the pod spec")
}

// TestReconciler_EvictsContainerRemovedFromSpecAndStatus guards the negative
// contract: a container absent from BOTH the pod spec and all status lists is
// genuinely reaped and must still be evicted (after the removal grace).
func TestReconciler_EvictsContainerRemovedFromSpecAndStatus(t *testing.T) {
	c, k8s := newEphemeralTestCache(t)

	seedNamedEntry(c, "gone-id", "gone", "pod-gone", "ns-gone", "uid-gone")
	k8s.setPod("ns-gone", "pod-gone", &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-gone", Namespace: "ns-gone", UID: types.UID("uid-gone")},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:        "app",
				ContainerID: "containerd://app-id3",
				State:       corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			}},
		},
	})

	c.reconcileOnce(context.Background()) // marks (grace)
	time.Sleep(80 * time.Millisecond)
	c.reconcileOnce(context.Background()) // evicts
	require.Nil(t, c.GetProjectedContainerProfile("gone-id"),
		"a container absent from spec and status must be evicted after the grace")
}

// TestReconciler_TerminationMarkResetsWhenContainerReappears pins the
// mark-and-sweep hygiene: if a tick classifies a container as
// terminated/reaped (mark) but a later tick sees it alive again, the mark must
// be reset — a subsequent genuine termination gets a fresh full grace window
// instead of an instant eviction against a stale mark.
func TestReconciler_TerminationMarkResetsWhenContainerReappears(t *testing.T) {
	c, k8s := newEphemeralTestCache(t)

	seedNamedEntry(c, "flap-id", "flap", "pod-flap", "ns-flap", "uid-flap")

	reaped := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-flap", Namespace: "ns-flap", UID: types.UID("uid-flap")},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:        "app",
				ContainerID: "containerd://app-id4",
				State:       corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			}},
		},
	}
	running := reaped.DeepCopy()
	running.Status.ContainerStatuses = append(running.Status.ContainerStatuses, corev1.ContainerStatus{
		Name:        "flap",
		ContainerID: "containerd://flap-id",
		State:       corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
	})

	k8s.setPod("ns-flap", "pod-flap", reaped)
	c.reconcileOnce(context.Background()) // marks
	time.Sleep(80 * time.Millisecond)     // grace elapses against the stale mark

	k8s.setPod("ns-flap", "pod-flap", running)
	c.reconcileOnce(context.Background()) // alive again: must reset the mark

	k8s.setPod("ns-flap", "pod-flap", reaped)
	c.reconcileOnce(context.Background()) // first observation of the NEW termination
	require.NotNil(t, c.GetProjectedContainerProfile("flap-id"),
		"a fresh termination after a live observation must get a full new grace window")
}
