package processtree

import (
	"os"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	processtreecreator "github.com/kubescape/node-agent/pkg/processtree/creator"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestManager_GetProcessBootTimeNs exercises the accessor that the network-stream
// attribution work calls to build a per-connection process reference: a procfs
// event reported through the manager must surface its boot-relative start time.
func TestManager_GetProcessBootTimeNs(t *testing.T) {
	creator := processtreecreator.NewProcessTreeCreator(containerprocesstree.NewContainerProcessTree(), config.Config{})
	mgr := NewProcessTreeManager(creator, containerprocesstree.NewContainerProcessTree(), config.Config{})

	require.NoError(t, mgr.ReportEvent(utils.ProcfsEventType, &events.ProcfsEvent{
		PID: 77, PPID: 1, Comm: "worker", StartTimeNs: 2_340_000_000,
	}))

	assert.Equal(t, uint64(2_340_000_000), mgr.GetProcessBootTimeNs(77))
	assert.Zero(t, mgr.GetProcessBootTimeNs(1234), "a pid the tree has never seen reads as 0")
}

// TestManager_GetContainerProcessTree_CarriesStartTime is the end-to-end guard
// for the trap this change exists to avoid: the start time is populated on the
// creator's node, but every consumer reads it through a copy function that
// strips any field it does not explicitly list. This walks the real production
// path — procfs event -> ProcessTreeManager.ReportEvent -> creator ->
// containerprocesstree.buildBranchToShim -> GetContainerProcessTree — against a
// creator-populated tree rather than a hand-built fixture, so it fails if the
// branch builder ever stops carrying StartTime again.
//
// The container is registered through the real ContainerCallback, which derives
// the shim pid by reading the container pid's parent from /proc. That needs a
// pid that actually exists, so the test uses its own.
func TestManager_GetContainerProcessTree_CarriesStartTime(t *testing.T) {
	containerTree := containerprocesstree.NewContainerProcessTree()
	creator := processtreecreator.NewProcessTreeCreator(containerTree, config.Config{})
	mgr := NewProcessTreeManager(creator, containerTree, config.Config{})

	self := uint32(os.Getpid())
	shim := uint32(os.Getppid())
	require.NotEqual(t, self, shim, "test needs a distinct parent pid")

	const containerID = "e2e-start-time-container"
	containerTree.ContainerCallback(containercollection.PubSubEvent{
		Type: containercollection.EventTypeAddContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
					ContainerID:  containerID,
					ContainerPID: self,
				},
			},
		},
	})

	shimWall := time.Date(2026, 7, 29, 9, 0, 0, 0, time.UTC)
	selfWall := time.Date(2026, 7, 29, 9, 30, 0, 0, time.UTC)

	require.NoError(t, mgr.ReportEvent(utils.ProcfsEventType, &events.ProcfsEvent{
		PID: shim, PPID: 1, Comm: "containerd-shim",
		StartTimeNs: 1_110_000_000, StartTimeWall: shimWall,
	}))
	require.NoError(t, mgr.ReportEvent(utils.ProcfsEventType, &events.ProcfsEvent{
		PID: self, PPID: shim, Comm: "nginx",
		StartTimeNs: 2_220_000_000, StartTimeWall: selfWall,
	}))

	branch, err := mgr.GetContainerProcessTree(containerID, self, false)
	require.NoError(t, err)
	assert.Equal(t, self, branch.PID)
	assert.Equal(t, selfWall, branch.StartTime,
		"the branch handed to alerts must carry the creator-populated StartTime")

	// The boot-relative identity for the same process, from the side map.
	assert.Equal(t, uint64(2_220_000_000), mgr.GetProcessBootTimeNs(self))
}
