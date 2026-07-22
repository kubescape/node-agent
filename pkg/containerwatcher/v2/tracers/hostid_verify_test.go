package tracers

import (
	"context"
	"sync"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"

	armotypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHostContainerID_RealProcfsScan runs the REAL ProcfsTracer against this
// machine's live /proc with an empty container collection — i.e. the bare-VM
// host scenario (no containers tracked). It verifies empirically that
// host-level processes are assigned the container ID "host"
// (armotypes.HostContainerID), NOT an empty string.
//
// Pure Go, no eBPF, no root required: the procfs feeder just reads /proc.
func TestHostContainerID_RealProcfsScan(t *testing.T) {
	// Sanity: the reserved host container ID is the literal "host".
	require.Equal(t, "host", armotypes.HostContainerID)

	cc := &containercollection.ContainerCollection{}
	tc, err := tracercollection.NewTracerCollection(cc)
	require.NoError(t, err)

	var (
		mu       sync.Mutex
		ids      = map[string]int{}
		total    int
		emptyIDs int
	)
	callback := func(_ utils.K8sEvent, containerID string, _ uint32) {
		mu.Lock()
		defer mu.Unlock()
		total++
		ids[containerID]++
		if containerID == "" {
			emptyIDs++
		}
	}

	tracer := NewProcfsTracer(
		cc,
		tc,
		containercollection.ContainerSelector{},
		callback,
		nil,
		config.Config{
			EnableRuntimeDetection: true,
			ProcfsScanInterval:     300 * time.Millisecond,
			// Large so the exit-scan path (which would need a ProcessTreeManager)
			// never fires during this short test.
			ProcfsPidScanInterval: 10 * time.Minute,
		},
		nil, // no ProcessTreeManager needed for the full /proc scan path
	)

	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, tracer.Start(ctx))

	// Let it complete at least one full /proc scan.
	time.Sleep(1500 * time.Millisecond)
	cancel()
	_ = tracer.Stop()

	mu.Lock()
	defer mu.Unlock()

	t.Logf("scanned %d host process events; distinct container IDs: %v", total, ids)

	require.Greater(t, total, 0, "expected the procfs scan to observe at least one process on this host")
	assert.Equal(t, 0, emptyIDs, "no host process event should carry an EMPTY container ID")
	assert.Equal(t, total, ids[armotypes.HostContainerID],
		"every host process event should carry container ID %q", armotypes.HostContainerID)
	assert.NotContains(t, ids, "", "the empty string must never appear as a host container ID")
}

// TestHostContainerID_ContainerBranch proves the "host" assignment is a
// deliberate else-branch, not a catch-all: when a container IS present in the
// collection for a given mount namespace, the lookup that procfs.go uses
// returns that container's real ID; for an unknown mount namespace it returns
// nil, which is exactly what routes the event to armotypes.HostContainerID.
func TestHostContainerID_ContainerBranch(t *testing.T) {
	cc := &containercollection.ContainerCollection{}

	const knownMntns = uint64(4026999999)
	const unknownMntns = uint64(4026000001)

	c := &containercollection.Container{Mntns: knownMntns}
	c.Runtime.ContainerID = "deadbeefcafe0001"
	cc.AddContainer(c)

	// Container branch: a tracked mntns resolves to the real container ID.
	got := cc.LookupContainerByMntns(knownMntns)
	require.NotNil(t, got, "expected the added container to be found by its mount namespace")
	assert.Equal(t, "deadbeefcafe0001", got.Runtime.ContainerID)

	// Host branch: an untracked mntns resolves to nil -> procfs.go assigns "host".
	assert.Nil(t, cc.LookupContainerByMntns(unknownMntns),
		"an untracked mount namespace must not resolve to a container; procfs.go then assigns %q", armotypes.HostContainerID)
}
