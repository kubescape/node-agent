package processtreecreator

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	"github.com/kubescape/node-agent/pkg/processtree/conversion"
	"github.com/stretchr/testify/require"
)

const ancestryContainerID = "delayed-ancestry"

func newAncestryTestCreator(t *testing.T) (*processTreeCreatorImpl, containerprocesstree.ContainerProcessTree, uint32) {
	t.Helper()
	tree := containerprocesstree.NewContainerProcessTree()
	const containerID = ancestryContainerID
	shim := uint32(os.Getppid())
	tree.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: &containercollection.Container{Runtime: containercollection.RuntimeMetadata{BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{ContainerID: containerID, ContainerPID: uint32(os.Getpid())}}},
	})
	creator := NewProcessTreeCreator(tree, createTestConfig(true)).(*processTreeCreatorImpl)
	creator.readStartTime = func(uint32) (uint64, time.Time) { return 0, time.Time{} }
	creator.processMap.Set(shim, &armotypes.Process{PID: shim, PPID: 1})
	return creator, tree, shim
}

func TestExecPreservesDelayedAncestry(t *testing.T) {
	creator, tree, shim := newAncestryTestCreator(t)
	const containerID = ancestryContainerID
	const root, parent, child, target = uint32(4000000100), uint32(4000000200), uint32(4000000300), uint32(4000000400)
	creator.FeedEvent(conversion.ProcessEvent{Type: conversion.ExecEvent, PID: target, PPID: child, Comm: "python3", Cmdline: "python3 spawner.py 4", ContainerID: containerID})
	require.Equal(t, child, creator.processMap.Get(target).PPID, "unknown ancestry must retain the actual parent")
	require.Equal(t, "python3 spawner.py 4", creator.processMap.Get(target).Cmdline)
	_, err := tree.GetPidBranch(containerID, target, &creator.processMap)
	require.Error(t, err, "missing ancestry must not be exported as a synthetic shim child")
	for _, event := range []conversion.ProcessEvent{
		{PID: child, PPID: parent}, {PID: parent, PPID: root}, {PID: root, PPID: shim},
	} {
		event.Type = conversion.ForkEvent
		event.ContainerID = containerID
		creator.FeedEvent(event)
	}
	branch, err := tree.GetPidBranch(containerID, target, &creator.processMap)
	require.NoError(t, err)
	current := &branch
	for _, pid := range []uint32{root, parent, child, target} {
		require.Equal(t, pid, current.PID)
		if pid != target {
			require.Len(t, current.ChildrenMap, 1)
			for _, next := range current.ChildrenMap {
				current = next
			}
		}
	}
	require.Equal(t, "python3 spawner.py 4", current.Cmdline)
}

func TestExecAncestryBoundaries(t *testing.T) {
	const target, parent, other = uint32(4000000400), uint32(4000000300), uint32(4000000200)
	for _, tc := range []struct {
		name       string
		parent     uint32
		setup      func(*processTreeCreatorImpl)
		wantParent uint32
		exported   bool
	}{
		{name: "missing parent", parent: parent, wantParent: parent},
		{name: "placeholder parent", parent: parent, setup: func(c *processTreeCreatorImpl) { c.processMap.Set(parent, &armotypes.Process{PID: parent}) }, wantParent: parent},
		{name: "host ancestry", parent: parent, setup: func(c *processTreeCreatorImpl) { c.processMap.Set(parent, &armotypes.Process{PID: parent, PPID: 1}) }, exported: true},
		{name: "parentless exec", exported: true},
		{name: "self parent", parent: target},
		{name: "cyclic parent chain", parent: parent, setup: func(c *processTreeCreatorImpl) {
			c.processMap.Set(parent, &armotypes.Process{PID: parent, PPID: other})
			c.processMap.Set(other, &armotypes.Process{PID: other, PPID: parent})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, tree, shim := newAncestryTestCreator(t)
			if tc.setup != nil {
				tc.setup(c)
			}
			c.FeedEvent(conversion.ProcessEvent{Type: conversion.ExecEvent, PID: target, PPID: tc.parent, Comm: "python3", Cmdline: "python3 spawner.py", ContainerID: ancestryContainerID})
			wantParent := tc.wantParent
			if tc.exported {
				wantParent = shim
			}
			require.Equal(t, wantParent, c.processMap.Get(target).PPID)
			require.Equal(t, "python3 spawner.py", c.processMap.Get(target).Cmdline)
			branch, err := tree.GetPidBranch(ancestryContainerID, target, &c.processMap)
			if tc.exported {
				require.NoError(t, err)
				require.Equal(t, target, branch.PID)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestExecWithMissingParentDoesNotLoseItOnZeroPPID(t *testing.T) {
	c, tree, _ := newAncestryTestCreator(t)
	const target, parent = uint32(4000000400), uint32(4000000300)
	c.FeedEvent(conversion.ProcessEvent{Type: conversion.ExecEvent, PID: target, PPID: parent, ContainerID: ancestryContainerID})
	c.FeedEvent(conversion.ProcessEvent{Type: conversion.ExecEvent, PID: target, Comm: "updated", ContainerID: ancestryContainerID})
	require.Equal(t, parent, c.processMap.Get(target).PPID)
	require.Equal(t, "updated", c.processMap.Get(target).Comm)
	_, err := tree.GetPidBranch(ancestryContainerID, target, &c.processMap)
	require.Error(t, err)
}

func TestExecDoesNotTransplantForeignAncestors(t *testing.T) {
	c, tree, shim := newAncestryTestCreator(t)
	// A real child registers a second shim through the same callback as production.
	child := exec.Command("sleep", "30")
	require.NoError(t, child.Start())
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	const foreignID = "foreign-container"
	foreignShim := uint32(os.Getpid())
	tree.ContainerCallback(containercollection.PubSubEvent{Type: containercollection.EventTypeAddContainer,
		Container: &containercollection.Container{Runtime: containercollection.RuntimeMetadata{BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{ContainerID: foreignID, ContainerPID: uint32(child.Process.Pid)}}}})
	const target, parent = uint32(4000000400), uint32(4000000300)
	c.processMap.Set(foreignShim, &armotypes.Process{PID: foreignShim})
	c.FeedEvent(conversion.ProcessEvent{Type: conversion.ForkEvent, PID: parent, PPID: foreignShim, ContainerID: foreignID})
	c.FeedEvent(conversion.ProcessEvent{Type: conversion.ExecEvent, PID: target, PPID: parent, Comm: "python3", ContainerID: ancestryContainerID})
	require.Equal(t, parent, c.processMap.Get(target).PPID, "foreign shim without a known host boundary remains unresolved")
	_, err := tree.GetPidBranch(ancestryContainerID, target, &c.processMap)
	require.Error(t, err)
	c.processMap.Get(foreignShim).PPID = 1
	c.FeedEvent(conversion.ProcessEvent{Type: conversion.ExecEvent, PID: target, PPID: parent, Comm: "python3", ContainerID: ancestryContainerID})
	require.Equal(t, shim, c.processMap.Get(target).PPID)
	require.Equal(t, foreignShim, c.processMap.Get(parent).PPID, "foreign ancestor must not be moved")
	branch, err := tree.GetPidBranch(ancestryContainerID, target, &c.processMap)
	require.NoError(t, err)
	require.Equal(t, target, branch.PID)
	foreignBranch, err := tree.GetPidBranch(foreignID, parent, &c.processMap)
	require.NoError(t, err)
	require.Empty(t, foreignBranch.ChildrenMap, "moving the exec must unlink it from its former parent")
}

func TestExecDirectContainerRoot(t *testing.T) {
	c, tree, shim := newAncestryTestCreator(t)
	const target = uint32(4000000400)
	c.FeedEvent(conversion.ProcessEvent{Type: conversion.ExecEvent, PID: target, PPID: shim, ContainerID: ancestryContainerID})
	branch, err := tree.GetPidBranch(ancestryContainerID, target, &c.processMap)
	require.NoError(t, err)
	require.Equal(t, shim, branch.PPID)
}
