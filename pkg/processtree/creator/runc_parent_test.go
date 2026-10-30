package processtreecreator

import (
	"os"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/processtree/conversion"
	"github.com/stretchr/testify/require"
)

const runcPID, execPID, execChildPID = uint32(4000000500), uint32(4000000600), uint32(4000000700)

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

func execUnderRunc(c *processTreeCreatorImpl, pid, ppid uint32, comm string) {
	c.FeedEvent(conversion.ProcessEvent{Type: conversion.ExecEvent, PID: pid, PPID: ppid, Comm: comm, Pcomm: "runc", ContainerID: ancestryContainerID})
}

func TestExecRereadsRuncParentToShim(t *testing.T) {
	c, tree, shim := newAncestryTestCreator(t)
	calls := 0
	c.readParent = stubParentReader(map[uint32][2]uint64{execPID: {uint64(shim), 0}}, &calls)

	execUnderRunc(c, execPID, runcPID, "sh")
	require.Equal(t, 1, calls)
	require.Equal(t, shim, c.processMap.Get(execPID).PPID, "the exec must be reparented to the shim")
	require.NotContains(t, c.processMap.Get(runcPID).ChildrenMap, armotypes.CommPID{PID: execPID}, "runc placeholder must drop the child")

	// A child of the repaired process resolves through the shim with full depth.
	c.FeedEvent(conversion.ProcessEvent{Type: conversion.ExecEvent, PID: execChildPID, PPID: execPID, Comm: "sleep", ContainerID: ancestryContainerID})
	require.Equal(t, 1, calls, "a known parent chain must not re-read /proc")
	branch, err := tree.GetPidBranch(ancestryContainerID, execChildPID, &c.processMap)
	require.NoError(t, err)
	require.Equal(t, execPID, branch.PID)
	require.Len(t, branch.ChildrenMap, 1)
	for _, child := range branch.ChildrenMap {
		require.Equal(t, execChildPID, child.PID)
	}
}

func TestExecRereadsAncestorWhenChildExecsFirst(t *testing.T) {
	c, tree, shim := newAncestryTestCreator(t)
	calls := 0
	table := map[uint32][2]uint64{execPID: {uint64(runcPID), 0}}
	c.readParent = stubParentReader(table, &calls)

	// runc still alive when the exec is handled: the parent stays runc.
	execUnderRunc(c, execPID, runcPID, "sh")
	require.Equal(t, runcPID, c.processMap.Get(execPID).PPID)

	// runc exits; the child's exec repairs its parent's chain.
	c.pidStartTimeNs[execPID] = 5_000_000_000
	table[execPID] = [2]uint64{uint64(shim), 5_000_000_000}
	c.FeedEvent(conversion.ProcessEvent{Type: conversion.ExecEvent, PID: execChildPID, PPID: execPID, Comm: "sleep", ContainerID: ancestryContainerID})
	require.Equal(t, shim, c.processMap.Get(execPID).PPID)
	_, err := tree.GetPidBranch(ancestryContainerID, execChildPID, &c.processMap)
	require.NoError(t, err)
}

func TestExecRereadRejectsRecycledAncestor(t *testing.T) {
	for _, tc := range []struct {
		name      string
		recorded  uint64
		readStart uint64
	}{
		{name: "start time differs", recorded: 5_000_000_000, readStart: 6_000_000_000},
		{name: "ancestor identity unknown", recorded: 0, readStart: 6_000_000_000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _, shim := newAncestryTestCreator(t)
			calls := 0
			table := map[uint32][2]uint64{execPID: {uint64(runcPID), 0}}
			c.readParent = stubParentReader(table, &calls)
			execUnderRunc(c, execPID, runcPID, "sh")
			if tc.recorded != 0 {
				c.pidStartTimeNs[execPID] = tc.recorded
			}
			table[execPID] = [2]uint64{uint64(shim), tc.readStart}
			c.FeedEvent(conversion.ProcessEvent{Type: conversion.ExecEvent, PID: execChildPID, PPID: execPID, ContainerID: ancestryContainerID})
			require.Equal(t, runcPID, c.processMap.Get(execPID).PPID)
		})
	}
}

func TestExecRereadRejectsYoungerParent(t *testing.T) {
	c, _, shim := newAncestryTestCreator(t)
	calls := 0
	c.readParent = stubParentReader(map[uint32][2]uint64{execPID: {uint64(shim), 5_000_000_000}}, &calls)
	c.pidStartTimeNs[shim] = 9_000_000_000
	execUnderRunc(c, execPID, runcPID, "sh")
	require.Equal(t, 1, calls)
	require.Equal(t, runcPID, c.processMap.Get(execPID).PPID)
}

func TestExecRereadKeepsParentWhenUnresolved(t *testing.T) {
	for _, tc := range []struct {
		name  string
		table map[uint32][2]uint64
	}{
		{name: "pid vanished", table: map[uint32][2]uint64{}},
		{name: "ppid unchanged", table: map[uint32][2]uint64{execPID: {uint64(runcPID), 0}}},
		{name: "ppid not in tree", table: map[uint32][2]uint64{execPID: {4000000999, 0}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, tree, _ := newAncestryTestCreator(t)
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
