package v1

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	mapset "github.com/deckarep/golang-set/v2"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/hostidentity"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sharedDataSpy counts every shared-data read so a test can assert the
// waitForSharedContainerData path was never entered.
type sharedDataSpy struct {
	objectcache.K8sObjectCacheMock
	reads int
}

func (s *sharedDataSpy) GetSharedContainerData(containerID string) *objectcache.WatchedContainerData {
	s.reads++
	return s.K8sObjectCacheMock.GetSharedContainerData(containerID)
}

func hostAddNotif() containercollection.PubSubEvent {
	return containercollection.PubSubEvent{
		Type: containercollection.EventTypeAddContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					ContainerID:   armotypes.HostContainerID,
					ContainerName: "host",
					ContainerPID:  1,
					// Deliberately non-empty: the host must be stopped by the
					// IsHostContainer check itself, not incidentally by the
					// empty-image-name check that follows it.
					ContainerImageName: "should-never-be-scanned",
				},
			},
			K8s: containercollection.K8sMetadata{
				BasicK8sMetadata: types.BasicK8sMetadata{Namespace: "host", PodName: "host-node-1", ContainerName: "host"},
			},
		},
	}
}

// Test_ContainerCallback_HostNeverReachesSharedDataWait is a
// regression guard for sbom_manager.go's waitForSharedContainerData.
//
// Host short-circuits at the IsHostContainer early return, long before
// awaitAndSubmit, so this shared-data read must be UNREACHABLE for host. That
// is asserted directly: the shared data IS primed (as it now is in production),
// so a read would succeed and silently carry the host into the
// image/mount-driven container scan path. Nothing reads it.
//
// A host-specific scan branch has since replaced that early return,
// so host monitoring is enabled here and the host scan is stubbed out: the
// point of the test is that the branch is reached WITHOUT ever consulting
// shared container data. If host were ever allowed to fall through to the
// container path instead, this test fails.
func Test_ContainerCallback_HostNeverReachesSharedDataWait(t *testing.T) {
	spy := &sharedDataSpy{}
	spy.SetSharedContainerData(armotypes.HostContainerID, hostidentity.BuildHostWatchedContainerData("node-1"))
	spy.reads = 0 // ignore the priming write's bookkeeping

	sm := &SbomManager{
		ctx:            t.Context(),
		cfg:            config.Config{HostMonitoringEnabled: true, NodeName: "node-1"},
		k8sObjectCache: spy,
		processing:     mapset.NewSet[string](),
		waitCancels:    map[string]context.CancelFunc{},
		hostScanFn:     func(string) {},
	}

	sm.ContainerCallback(hostAddNotif())

	// Give any mistakenly spawned await goroutine a window to perform a read.
	time.Sleep(200 * time.Millisecond)

	assert.Zero(t, spy.reads, "host must never reach sbom_manager's shared-data read")
	assert.Zero(t, sm.processing.Cardinality(), "host must never be registered as an in-flight SBOM scan")
	assert.Empty(t, sm.waitCancels, "host must never register a shared-data wait cancel")
}

// Test_sharedDataSpy_CountsReads is the positive control for the assertion
// above: it proves a read of the primed host entry is both possible and
// counted, so "zero reads" is evidence of the early return, not of a spy that
// never fires.
func Test_sharedDataSpy_CountsReads(t *testing.T) {
	spy := &sharedDataSpy{}
	spy.SetSharedContainerData(armotypes.HostContainerID, hostidentity.BuildHostWatchedContainerData("node-1"))
	spy.reads = 0
	sm := &SbomManager{ctx: t.Context(), k8sObjectCache: spy}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	data, err := sm.waitForSharedContainerData(ctx, armotypes.HostContainerID)

	require.NoError(t, err)
	require.NotNil(t, data)
	assert.Equal(t, armotypes.HostContainerID, data.ContainerID)
	assert.Positive(t, spy.reads, "the spy must count reads, otherwise the zero-read assertion is vacuous")
}

// Test_CreateSbomManager_HostFSPrefixMatchesHostRoot proves hostFSPrefix and
// hostRoot always agree. They used to be resolved independently: hostRoot
// from a local HOST_ROOT lookup falling back to "/host" (matching the
// DaemonSet's actual mount, see tests/chart/templates/node-agent/
// daemonset.yaml), and hostFSPrefix from hostsensormanager.HostFSPrefix(),
// whose own fallback is "/host_fs" -- a different default for the same env
// var. With HOST_ROOT unset, the host SBOM scan would have silently opened a
// path the DaemonSet never mounts.
func Test_CreateSbomManager_HostFSPrefixMatchesHostRoot(t *testing.T) {
	if orig, ok := os.LookupEnv("HOST_ROOT"); ok {
		t.Cleanup(func() { _ = os.Setenv("HOST_ROOT", orig) })
	}
	require.NoError(t, os.Unsetenv("HOST_ROOT"))

	sm, err := CreateSbomManager(t.Context(), config.Config{}, "/tmp/sbom-manager-test.sock", nil, nil, nil, nil, nil)
	require.NoError(t, err)

	assert.Equal(t, "/host", sm.hostFSPrefix, "hostFSPrefix must fall back to the same default as hostRoot")
	assert.Equal(t, sm.hostRoot, sm.hostFSPrefix, "hostFSPrefix and hostRoot must always agree")
}
