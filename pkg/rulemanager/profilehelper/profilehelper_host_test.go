package profilehelper

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/hostidentity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

// TestGetPodSpec_HostContainer is a guard test for the host container path.
//
// GetSharedContainerData(armotypes.HostContainerID) returns a
// NON-nil synthetic entry (Namespace "host", PodName "host-<hostID>") that is
// not backed by any real Kubernetes Pod. Without a guard, GetPodSpec would run
// a live pod-spec lookup on those synthetic coordinates. This test proves the
// host path:
//   - never performs the live lookup (a deliberately "wrong" pod spec is
//     installed in the cache; if the lookup ran, we would get it back), and
//   - returns a usable, explicitly EMPTY pod spec with no error, rather than a
//     misleading "pod spec not found" that reads like a transient failure.
func TestGetPodSpec_HostContainer(t *testing.T) {
	objCache := newMock()
	objCache.SetSharedContainerData(armotypes.HostContainerID, hostidentity.BuildHostWatchedContainerData("node-1"))

	// A pod spec that must NOT be returned for host: the mock's GetPodSpec
	// ignores namespace/podName, so returning it would prove the live lookup ran.
	objCache.SetPodSpec(&corev1.PodSpec{
		Containers: []corev1.Container{{Name: "some-real-container", Command: []string{"/bin/sh"}}},
	})

	got, err := GetPodSpec(objCache, armotypes.HostContainerID)

	require.NoError(t, err, "host must not surface a pod-spec lookup failure as an error")
	require.NotNil(t, got, "host must get a usable pod spec, not nil")
	assert.Empty(t, got.Containers, "host pod spec must be empty, never the cache's real-container spec")
	assert.Equal(t, &corev1.PodSpec{}, got, "host must get an explicitly empty spec, not a fabricated one")
}

// TestGetPodSpec_NonHostStillLooksUp pins that the host guard did not change
// the behaviour of a real container: the live pod-spec lookup still runs and
// its result is still returned.
func TestGetPodSpec_NonHostStillLooksUp(t *testing.T) {
	objCache := newMock()
	objCache.SetSharedContainerData("cid", hostidentity.BuildHostWatchedContainerData("node-1"))
	objCache.SetPodSpec(&corev1.PodSpec{
		Containers: []corev1.Container{{Name: "some-real-container"}},
	})

	got, err := GetPodSpec(objCache, "cid")

	require.NoError(t, err)
	require.Len(t, got.Containers, 1, "a non-host container must still get the looked-up pod spec")
	assert.Equal(t, "some-real-container", got.Containers[0].Name)
}

// TestGetContainerName_HostContainer proves the sibling helper is also
// host-safe with the synthetic data.
//
// hostidentity.BuildHostWatchedContainerData now
// explicitly sets a single synthetic ContainerInfos entry (name "host"),
// fixing a real crash this docstring used to describe as the safe case --
// containerprofilemanager/v1/monitoring.go's saveContainerProfile
// unconditionally indexes ContainerInfos[ContainerType][ContainerIndex] when
// building the host ContainerProfile CR, which panicked on the previously nil
// ContainerInfos. With that fix in place, GetContainerName correctly returns
// the synthetic container's name instead of "" -- it is no longer "no name
// fabricated", it is "the one real (synthetic-but-intentional) name the host
// entry carries", exactly like GetContainerName does for any other container.
func TestGetContainerName_HostContainer(t *testing.T) {
	objCache := newMock()
	objCache.SetSharedContainerData(armotypes.HostContainerID, hostidentity.BuildHostWatchedContainerData("node-1"))

	assert.Equal(t, armotypes.HostContainerID, GetContainerName(objCache, armotypes.HostContainerID))
}
