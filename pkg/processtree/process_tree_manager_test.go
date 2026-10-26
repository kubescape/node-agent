package processtree

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	treeconfig "github.com/kubescape/node-agent/pkg/processtree/config"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	processtreecreator "github.com/kubescape/node-agent/pkg/processtree/creator"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManager_GetContainerProcessTree_HostRetainsExitedProcess(t *testing.T) {
	cfg := config.Config{ExitCleanup: treeconfig.ExitCleanupConfig{
		MaxPendingExits: 100, CleanupInterval: time.Hour, CleanupDelay: 5 * time.Minute,
	}}
	containerTree := containerprocesstree.NewContainerProcessTree()
	creator := processtreecreator.NewProcessTreeCreator(containerTree, cfg)
	mgr := NewProcessTreeManager(creator, containerTree, cfg)
	containerTree.ContainerCallback(containercollection.PubSubEvent{
		Type: containercollection.EventTypeAddContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{ContainerID: "host", ContainerPID: 1},
			},
		},
	})
	require.NoError(t, mgr.ReportEvent(utils.ProcfsEventType, &events.ProcfsEvent{
		PID: 1, Comm: "systemd", Path: "/usr/lib/systemd/systemd", ContainerID: "host",
	}))

	// A synthetic PID above Linux's PID limit ensures procfs cannot supply the
	// executable or arguments. Feed exec then exit through the real manager.
	const pid uint32 = 1 << 30
	require.NoError(t, mgr.ReportEvent(utils.ExecveEventType, &utils.StructEvent{
		ContainerID: "host", Pid: pid, Ppid: 1, Comm: "ps",
		ExePath: "/usr/bin/ps", Args: []string{"ps", "aux"}, Timestamp: time.Now().UnixNano(),
	}))
	require.NoError(t, mgr.ReportEvent(utils.ExitEventType, &utils.StructEvent{
		ContainerID: "host", Pid: pid, Ppid: 1, Timestamp: time.Now().UnixNano(),
	}))
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	require.True(t, os.IsNotExist(err))

	for _, useCache := range []bool{false, true} {
		branch, err := mgr.GetContainerProcessTree("host", pid, useCache)
		require.NoError(t, err)
		require.Equal(t, uint32(1), branch.PID)
		require.Len(t, branch.ChildrenMap, 1)
		for _, child := range branch.ChildrenMap {
			assert.Equal(t, pid, child.PID)
			assert.Equal(t, "/usr/bin/ps", child.Path)
			assert.Equal(t, "ps aux", child.Cmdline)
		}
	}
}

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

	impl := mgr.(*ProcessTreeManagerImpl)
	key := treeCacheKey{containerID: containerID, pid: self}
	impl.containerProcessTreeCache.Add(key, armotypes.Process{Comm: "cached"})
	cached, err := mgr.GetContainerProcessTree(containerID, self, true)
	require.NoError(t, err)
	require.Equal(t, "cached", cached.Comm)
	bypassed, err := mgr.GetContainerProcessTree(containerID, self, false)
	require.NoError(t, err)
	require.Equal(t, "nginx", bypassed.Comm)
}

func TestManager_GetContainerProcessTree_FailedRefreshDropsCachedBranch(t *testing.T) {
	cfg := config.Config{KubernetesMode: true, ExitCleanup: treeconfig.ExitCleanupConfig{
		MaxPendingExits: 100, CleanupInterval: time.Hour, CleanupDelay: 5 * time.Minute,
	}}
	containerTree := containerprocesstree.NewContainerProcessTree()
	creator := processtreecreator.NewProcessTreeCreator(containerTree, cfg)
	mgr := NewProcessTreeManager(creator, containerTree, cfg)

	self := uint32(os.Getpid())
	shim := uint32(os.Getppid())
	require.NotEqual(t, self, shim, "test must run under a distinct parent pid")

	const containerID = "failed-refresh-container"
	containerTree.ContainerCallback(containercollection.PubSubEvent{
		Type: containercollection.EventTypeAddContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{ContainerID: containerID, ContainerPID: self},
			},
		},
	})
	require.NoError(t, mgr.ReportEvent(utils.ProcfsEventType, &events.ProcfsEvent{PID: shim, PPID: 1, Comm: "containerd-shim", ContainerID: containerID}))
	require.NoError(t, mgr.ReportEvent(utils.ProcfsEventType, &events.ProcfsEvent{PID: self, PPID: shim, Comm: "init", ContainerID: containerID}))

	const pid uint32 = 1 << 30
	require.NoError(t, mgr.ReportEvent(utils.ForkEventType, &utils.StructEvent{
		ContainerID: containerID, Pid: pid, Ppid: self, Comm: "python3", Timestamp: time.Now().UnixNano(),
	}))
	require.NoError(t, mgr.ReportEvent(utils.ExecveEventType, &utils.StructEvent{
		ContainerID: containerID, Pid: pid, Ppid: self, Comm: "python3",
		ExePath: "/usr/bin/python3", Args: []string{"python3", "worker.py", "--job", "1"}, Timestamp: time.Now().UnixNano(),
	}))
	branch, err := mgr.GetContainerProcessTree(containerID, pid, false)
	require.NoError(t, err)
	require.Equal(t, self, branch.PID)

	require.NoError(t, mgr.ReportEvent(utils.ExitEventType, &utils.StructEvent{
		ContainerID: containerID, Pid: pid, Ppid: self, Timestamp: time.Now().UnixNano(),
	}))
	require.NoError(t, mgr.ReportEvent(utils.ExecveEventType, &utils.StructEvent{
		ContainerID: containerID, Pid: pid, Ppid: pid + 7, Comm: "python3",
		ExePath: "/usr/bin/python3", Args: []string{"python3", "worker.py", "--job", "2"}, Timestamp: time.Now().UnixNano(),
	}))
	_, err = mgr.GetContainerProcessTree(containerID, pid, false)
	require.Error(t, err, "refresh must fail while the new parent is unknown")

	cached, err := mgr.GetContainerProcessTree(containerID, pid, true)
	require.Error(t, err, "cached read must not serve the previous process's branch")
	require.Zero(t, cached.PID)
}

func TestManager_GetContainerProcessTree_ConcurrentExitCleanup(t *testing.T) {
	cfg := config.Config{ExitCleanup: treeconfig.ExitCleanupConfig{
		MaxPendingExits: 100, CleanupInterval: time.Millisecond, CleanupDelay: 0,
	}}
	containerTree := containerprocesstree.NewContainerProcessTree()
	creator := processtreecreator.NewProcessTreeCreator(containerTree, cfg)
	mgr := NewProcessTreeManager(creator, containerTree, cfg)
	containerTree.ContainerCallback(containercollection.PubSubEvent{
		Type: containercollection.EventTypeAddContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{ContainerID: "host", ContainerPID: 1},
			},
		},
	})
	require.NoError(t, mgr.ReportEvent(utils.ProcfsEventType, &events.ProcfsEvent{PID: 1, Comm: "systemd", ContainerID: "host"}))
	mgr.Start()
	defer mgr.Stop()

	const parent, child uint32 = 1 << 30, 1<<30 + 1
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = mgr.GetContainerProcessTree("host", child, false)
			}
		}
	})
	for range 200 {
		now := time.Now().UnixNano()
		require.NoError(t, mgr.ReportEvent(utils.ExecveEventType, &utils.StructEvent{ContainerID: "host", Pid: parent, Ppid: 1, Comm: "sh", Timestamp: now}))
		require.NoError(t, mgr.ReportEvent(utils.ExecveEventType, &utils.StructEvent{ContainerID: "host", Pid: child, Ppid: parent, Comm: "sleep", Timestamp: now}))
		require.NoError(t, mgr.ReportEvent(utils.ExitEventType, &utils.StructEvent{ContainerID: "host", Pid: parent, Ppid: 1, Timestamp: now}))
		time.Sleep(2 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
}
