package processtreecreator

import (
	"os"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	"github.com/kubescape/node-agent/pkg/processtree/conversion"
	"github.com/stretchr/testify/require"
)

const runcPID, execPID, execChildPID = uint32(4000000500), uint32(4000000600), uint32(4000000700)

// Boot-relative times used by the runc tests. The exec happens after the
// process was created; a recycled pid reads a later creation time.
const (
	testWallOffsetNs = int64(1_700_000_000_000_000_000)
	shimStartNs      = uint64(1_000_000_000)
	execStartNs      = uint64(5_000_000_000)
	execBootNs       = uint64(5_500_000_000)
	recycledStartNs  = uint64(7_000_000_000)
	shimComm         = "containerd-shim"
)

// stubParentReader answers readParent from a fixed table and counts calls.
func stubParentReader(table map[uint32][2]uint64, calls *int) func(uint32) (uint32, uint64, bool) {
	return func(pid uint32) (uint32, uint64, bool) {
		*calls++
		e, ok := table[pid]
		if !ok {
			return 0, 0, false
		}
		return uint32(e[0]), e[1], true
	}
}

// newRuncTestCreator names the shim node and fixes the wall/boot offset so an
// exec stamped execBootNs maps back to the boot clock.
func newRuncTestCreator(t *testing.T) (*processTreeCreatorImpl, containerprocesstree.ContainerProcessTree, uint32) {
	t.Helper()
	c, tree, shim := newAncestryTestCreator(t)
	c.bootToWallNs = testWallOffsetNs
	c.processMap.Get(shim).Comm = shimComm
	return c, tree, shim
}

func execUnderRunc(c *processTreeCreatorImpl, pid, ppid uint32, comm string) {
	c.FeedEvent(conversion.ProcessEvent{Type: conversion.ExecEvent, PID: pid, PPID: ppid, Comm: comm, Pcomm: "runc", ContainerID: ancestryContainerID, StartTimeNs: uint64(testWallOffsetNs) + execBootNs})
}

func TestExecRereadsRuncParentToShim(t *testing.T) {
	c, tree, shim := newRuncTestCreator(t)
	calls := 0
	c.readParent = stubParentReader(map[uint32][2]uint64{execPID: {uint64(shim), execStartNs}, shim: {1, shimStartNs}}, &calls)

	execUnderRunc(c, execPID, runcPID, "sh")
	require.Equal(t, 2, calls)
	require.Equal(t, shim, c.processMap.Get(execPID).PPID, "the exec must be reparented to the shim")
	require.Equal(t, shimComm, c.processMap.Get(execPID).Pcomm, "the event's runc pcomm must not survive adoption")
	require.NotContains(t, c.processMap.Get(runcPID).ChildrenMap, armotypes.CommPID{PID: execPID}, "runc placeholder must drop the child")

	// A child of the repaired process resolves through the shim with full depth.
	c.FeedEvent(conversion.ProcessEvent{Type: conversion.ExecEvent, PID: execChildPID, PPID: execPID, Comm: "sleep", ContainerID: ancestryContainerID})
	require.Equal(t, 2, calls, "a known parent chain must not re-read /proc")
	branch, err := tree.GetPidBranch(ancestryContainerID, execChildPID, &c.processMap)
	require.NoError(t, err)
	require.Equal(t, execPID, branch.PID)
	require.Len(t, branch.ChildrenMap, 1)
	for _, child := range branch.ChildrenMap {
		require.Equal(t, execChildPID, child.PID)
	}
}

func TestExecRereadsAncestorWhenChildExecsFirst(t *testing.T) {
	c, tree, shim := newRuncTestCreator(t)
	calls := 0
	table := map[uint32][2]uint64{execPID: {uint64(runcPID), execStartNs}, shim: {1, shimStartNs}}
	c.readParent = stubParentReader(table, &calls)

	// runc still alive when the exec is handled: the parent stays runc.
	execUnderRunc(c, execPID, runcPID, "sh")
	require.Equal(t, runcPID, c.processMap.Get(execPID).PPID)
	require.Equal(t, "runc", c.processMap.Get(execPID).Pcomm)

	// runc exits; the child's exec repairs its parent's chain.
	c.pidStartTimeNs[execPID] = execStartNs
	table[execPID] = [2]uint64{uint64(shim), execStartNs}
	c.FeedEvent(conversion.ProcessEvent{Type: conversion.ExecEvent, PID: execChildPID, PPID: execPID, Comm: "sleep", Pcomm: "sh", ContainerID: ancestryContainerID, StartTimeNs: uint64(testWallOffsetNs) + execBootNs})
	require.Equal(t, shim, c.processMap.Get(execPID).PPID)
	require.Equal(t, shimComm, c.processMap.Get(execPID).Pcomm, "the repaired ancestor must name its adopted parent")
	require.Equal(t, "sh", c.processMap.Get(execChildPID).Pcomm, "the child's own parent is unchanged")
	_, err := tree.GetPidBranch(ancestryContainerID, execChildPID, &c.processMap)
	require.NoError(t, err)
}

func TestExecRereadRejectsRecycledAncestor(t *testing.T) {
	for _, tc := range []struct {
		name      string
		recorded  uint64
		readStart uint64
	}{
		{name: "start time differs", recorded: execStartNs, readStart: recycledStartNs},
		{name: "ancestor identity unknown", recorded: 0, readStart: recycledStartNs},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _, shim := newRuncTestCreator(t)
			calls := 0
			table := map[uint32][2]uint64{execPID: {uint64(runcPID), execStartNs}, shim: {1, shimStartNs}}
			c.readParent = stubParentReader(table, &calls)
			execUnderRunc(c, execPID, runcPID, "sh")
			if tc.recorded != 0 {
				c.pidStartTimeNs[execPID] = tc.recorded
			}
			table[execPID] = [2]uint64{uint64(shim), tc.readStart}
			// The child execs after the ancestor's /proc start time, so only the
			// identity guard under test can reject the repair.
			c.FeedEvent(conversion.ProcessEvent{Type: conversion.ExecEvent, PID: execChildPID, PPID: execPID, ContainerID: ancestryContainerID, StartTimeNs: uint64(testWallOffsetNs) + tc.readStart + 1_000_000_000})
			require.Equal(t, runcPID, c.processMap.Get(execPID).PPID)
		})
	}
}

// An exec handled after its pid was recycled: /proc describes the replacement,
// created after the exec instant, and its parent must not be adopted.
func TestExecRereadRejectsRecycledExecTarget(t *testing.T) {
	for _, tc := range []struct {
		name     string
		execWall uint64
	}{
		{name: "replacement created after the exec", execWall: uint64(testWallOffsetNs) + execBootNs},
		{name: "exec timestamp unknown", execWall: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _, shim := newRuncTestCreator(t)
			calls := 0
			start := recycledStartNs
			if tc.execWall == 0 {
				start = execStartNs
			}
			c.readParent = stubParentReader(map[uint32][2]uint64{execPID: {uint64(shim), start}, shim: {1, shimStartNs}}, &calls)
			c.FeedEvent(conversion.ProcessEvent{Type: conversion.ExecEvent, PID: execPID, PPID: runcPID, Comm: "sh", Pcomm: "runc", ContainerID: ancestryContainerID, StartTimeNs: tc.execWall})
			require.Equal(t, 1, calls)
			require.Equal(t, runcPID, c.processMap.Get(execPID).PPID, "the event's parent must be kept")
			require.Equal(t, "runc", c.processMap.Get(execPID).Pcomm)
		})
	}

	// Successive delayed execs: the first one records the replacement's start
	// time through ensureStartTime, so the second sees a matching recorded time
	// and must still be rejected by its exec timestamp.
	t.Run("successive delayed execs", func(t *testing.T) {
		c, _, shim := newRuncTestCreator(t)
		calls := 0
		c.readParent = stubParentReader(map[uint32][2]uint64{execPID: {uint64(shim), recycledStartNs}, shim: {1, shimStartNs}}, &calls)
		c.readStartTime = func(uint32) (uint64, time.Time) { return recycledStartNs, time.Time{} }
		execUnderRunc(c, execPID, runcPID, "sh")
		require.Equal(t, recycledStartNs, c.pidStartTimeNs[execPID], "the first exec caches the replacement's start time")
		execUnderRunc(c, execPID, runcPID, "sh")
		require.Equal(t, runcPID, c.processMap.Get(execPID).PPID, "the second delayed exec must not adopt the replacement's parent")
		require.Equal(t, "runc", c.processMap.Get(execPID).Pcomm)
	})
}

// A delayed parent exec caches its recycled pid's replacement start time. A
// queued child exec stamped before the replacement existed must not trust that
// cached value and attach the old ancestry to the replacement's parent.
func TestExecRereadRejectsAncestorCreatedAfterChildExec(t *testing.T) {
	c, _, shim := newRuncTestCreator(t)
	calls := 0
	c.readParent = stubParentReader(map[uint32][2]uint64{execPID: {uint64(shim), recycledStartNs}, shim: {1, shimStartNs}}, &calls)
	c.readStartTime = func(uint32) (uint64, time.Time) { return recycledStartNs, time.Time{} }
	execUnderRunc(c, execPID, runcPID, "sh")
	require.Equal(t, runcPID, c.processMap.Get(execPID).PPID)
	require.Equal(t, recycledStartNs, c.pidStartTimeNs[execPID], "the parent exec caches the replacement's start time")

	childExecBootNs := recycledStartNs - 1_000_000_000
	c.FeedEvent(conversion.ProcessEvent{Type: conversion.ExecEvent, PID: execChildPID, PPID: execPID, Comm: "sleep", Pcomm: "sh", ContainerID: ancestryContainerID, StartTimeNs: uint64(testWallOffsetNs) + childExecBootNs})
	require.Equal(t, runcPID, c.processMap.Get(execPID).PPID, "an ancestor created after the child's exec must not be repaired")
	require.Equal(t, "runc", c.processMap.Get(execPID).Pcomm)
}

// Two queued execs for the same pid both report runc. The first repairs the
// parent; the second keeps it and must not relabel Pcomm back to runc.
func TestExecRereadKeepsRepairedPcommOnSuccessiveExecs(t *testing.T) {
	c, _, shim := newRuncTestCreator(t)
	calls := 0
	c.readParent = stubParentReader(map[uint32][2]uint64{execPID: {uint64(shim), execStartNs}, shim: {1, shimStartNs}}, &calls)
	c.readStartTime = func(uint32) (uint64, time.Time) { return execStartNs, time.Time{} }
	execUnderRunc(c, execPID, runcPID, "sh")
	require.Equal(t, shim, c.processMap.Get(execPID).PPID)
	require.Equal(t, shimComm, c.processMap.Get(execPID).Pcomm)
	execUnderRunc(c, execPID, runcPID, "sh")
	require.Equal(t, shim, c.processMap.Get(execPID).PPID)
	require.Equal(t, shimComm, c.processMap.Get(execPID).Pcomm, "a stale runc pcomm must not overwrite the repaired parent's comm")
}

// The tree's node for the new ppid may be a stale, exited process whose pid was
// recycled; it must not be adopted.
func TestExecRereadRejectsStaleParentNode(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(c *processTreeCreatorImpl, shim uint32)
	}{
		{name: "recorded start time differs", setup: func(c *processTreeCreatorImpl, shim uint32) { c.pidStartTimeNs[shim] = shimStartNs + 1 }},
		{name: "pending exit", setup: func(c *processTreeCreatorImpl, shim uint32) { c.pendingExits[shim] = &pendingExit{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _, shim := newRuncTestCreator(t)
			calls := 0
			c.readParent = stubParentReader(map[uint32][2]uint64{execPID: {uint64(shim), execStartNs}, shim: {1, shimStartNs}}, &calls)
			tc.setup(c, shim)
			execUnderRunc(c, execPID, runcPID, "sh")
			require.Equal(t, runcPID, c.processMap.Get(execPID).PPID)
			require.Equal(t, "runc", c.processMap.Get(execPID).Pcomm)
		})
	}
}

func TestExecRereadRejectsYoungerParent(t *testing.T) {
	c, _, shim := newRuncTestCreator(t)
	calls := 0
	c.readParent = stubParentReader(map[uint32][2]uint64{execPID: {uint64(shim), execStartNs}, shim: {1, execStartNs + 1}}, &calls)
	execUnderRunc(c, execPID, runcPID, "sh")
	require.Equal(t, 2, calls)
	require.Equal(t, runcPID, c.processMap.Get(execPID).PPID)
}

func TestExecRereadKeepsParentWhenUnresolved(t *testing.T) {
	for _, tc := range []struct {
		name  string
		table map[uint32][2]uint64
	}{
		{name: "pid vanished", table: map[uint32][2]uint64{}},
		{name: "ppid unchanged", table: map[uint32][2]uint64{execPID: {uint64(runcPID), execStartNs}}},
		{name: "ppid not in tree", table: map[uint32][2]uint64{execPID: {4000000999, execStartNs}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, tree, _ := newRuncTestCreator(t)
			calls := 0
			c.readParent = stubParentReader(tc.table, &calls)
			execUnderRunc(c, execPID, runcPID, "sh")
			require.Equal(t, 1, calls)
			require.Equal(t, runcPID, c.processMap.Get(execPID).PPID)
			require.Equal(t, "sh", c.processMap.Get(execPID).Comm)
			_, ok := c.processMap.Load(4000000999)
			require.False(t, ok)
			_, err := tree.GetPidBranch(ancestryContainerID, execPID, &c.processMap)
			require.Error(t, err)
		})
	}
}

func TestExecRereadNotAttemptedOutsideKubernetes(t *testing.T) {
	c, _, shim := newAncestryTestCreator(t)
	c.config = createTestConfig(false)
	calls := 0
	c.readParent = stubParentReader(map[uint32][2]uint64{execPID: {uint64(shim), 0}}, &calls)
	execUnderRunc(c, execPID, runcPID, "sh")
	require.Zero(t, calls)
	require.Equal(t, runcPID, c.processMap.Get(execPID).PPID)
}

func TestExecRereadNotAttemptedForKnownParent(t *testing.T) {
	c, _, shim := newAncestryTestCreator(t)
	calls := 0
	c.readParent = stubParentReader(nil, &calls)
	c.FeedEvent(conversion.ProcessEvent{Type: conversion.ExecEvent, PID: execPID, PPID: shim, ContainerID: ancestryContainerID})
	require.Zero(t, calls)
}

func TestProcfsParentReaderReadsSelf(t *testing.T) {
	read := newProcfsParentReader()
	ppid, start, ok := read(uint32(os.Getpid()))
	require.True(t, ok)
	require.Equal(t, uint32(os.Getppid()), ppid)
	require.NotZero(t, start)
	wantStart, _ := newProcfsStartTimeReader()(uint32(os.Getpid()))
	require.Equal(t, wantStart, start)
	_, _, ok = read(4000000999)
	require.False(t, ok, "a vanished pid must report not ok")
}
