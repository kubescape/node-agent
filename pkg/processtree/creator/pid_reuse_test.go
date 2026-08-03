package processtreecreator

import (
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/config"
	processtreecreatorconfig "github.com/kubescape/node-agent/pkg/processtree/config"
	"github.com/kubescape/node-agent/pkg/processtree/conversion"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newReuseTestCreator builds a creator with a cleanup delay long enough that
// pending exits sit untouched until a test flushes them explicitly, and with no
// background loop running (Start is deliberately not called).
func newReuseTestCreator(t *testing.T) *processTreeCreatorImpl {
	t.Helper()

	pt := &processTreeCreatorImpl{
		processMap:            maps.SafeMap[uint32, *armotypes.Process]{},
		containerTree:         &mockContainerProcessTree{},
		reparentingStrategies: &mockReparentingLogic{},
		pendingExits:          make(map[uint32]*pendingExit),
		pidStartTimeNs:        make(map[uint32]uint64),
		config: config.Config{
			KubernetesMode: false,
			ExitCleanup: processtreecreatorconfig.ExitCleanupConfig{
				MaxPendingExits: 1000,
				CleanupInterval: time.Hour,
				CleanupDelay:    time.Hour,
			},
		},
	}

	// Neutralise the on-demand /proc start-time read. These synthetic pids must
	// not accidentally resolve against the container's real /proc, and several
	// premises here — "a fork-created node has no identity yet" — depend on the
	// side map holding exactly what the test fed it.
	pt.readStartTime = func(uint32) (uint64, time.Time) { return 0, time.Time{} }

	return pt
}

// flushPendingExits fires the delayed cleanup the way the background loop would.
func flushPendingExits(pt *processTreeCreatorImpl) {
	pt.mutex.Lock()
	defer pt.mutex.Unlock()
	for pid := range pt.pendingExits {
		pt.exitByPid(pid)
	}
}

// BUG 1 — inheritance. handleForkEvent fills only EMPTY fields, and a recycled
// pid's node is not empty: it still holds the dead process's identity. The new
// process therefore reports the dead one's comm, cmdline and path, and an alert
// raised in this window names the wrong command.
func TestPidReuse_ForkAfterExit_DoesNotInheritDeadFields(t *testing.T) {
	pt := newReuseTestCreator(t)

	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ForkEvent, PID: 100, PPID: 1, Comm: "malware"})
	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ExecEvent, PID: 100, PPID: 1, Comm: "malware",
		Cmdline: "malware --evil", Path: "/tmp/malware"})
	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ExitEvent, PID: 100, Comm: "exit", Timestamp: time.Now()})

	// The kernel recycles pid 100 for an innocent worker before cleanup fires.
	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ForkEvent, PID: 100, PPID: 2, Comm: "worker"})

	node, err := pt.GetProcessNode(100)
	require.NoError(t, err)
	require.NotNil(t, node)
	assert.Equal(t, "worker", node.Comm, "recycled pid must not report the dead process's comm")
	assert.NotEqual(t, "malware --evil", node.Cmdline, "recycled pid must not inherit the dead process's cmdline")
	assert.NotEqual(t, "/tmp/malware", node.Path, "recycled pid must not inherit the dead process's path")
}

// BUG 2 — delayed deletion. exitByPid matches on pid alone, so the dead
// process's exit, fired up to CleanupDelay after the fact, deletes whatever node
// holds that pid by then: here, a live process. Its children are reparented
// around a process that is still running.
func TestPidReuse_DelayedExit_DoesNotDeleteNewProcess(t *testing.T) {
	pt := newReuseTestCreator(t)

	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ForkEvent, PID: 100, PPID: 1, Comm: "old"})
	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ExitEvent, PID: 100, Comm: "exit", Timestamp: time.Now()})
	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ForkEvent, PID: 100, PPID: 2, Comm: "new"})

	flushPendingExits(pt)

	node, err := pt.GetProcessNode(100)
	require.NoError(t, err)
	assert.NotNil(t, node, "the new incarnation's node must survive the old incarnation's delayed exit")
}

// A pending exit can outlive its node: the exit may arrive for a pid the tree
// never created a node for, or another path may already have removed it. The pid
// is then recycled, the fork builds a fresh node, and the stale pending exit
// deletes THAT node when cleanup fires — the same corruption, reached without a
// stale node ever being found.
//
// So the guard has to run BEFORE the node lookup, not only in the branch where a
// stale node was found. Gating it on an existing node would leave this case open.
func TestPidReuse_ForkAfterExit_ConsumesPendingExitWithNoNode(t *testing.T) {
	pt := newReuseTestCreator(t)

	// An exit for a pid that has no node in the tree.
	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ExitEvent, PID: 100, Comm: "exit", Timestamp: time.Now()})

	pt.mutex.RLock()
	_, pending := pt.pendingExits[100]
	pt.mutex.RUnlock()
	require.True(t, pending, "precondition: a pending exit exists with no node behind it")

	// The kernel recycles the pid.
	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ForkEvent, PID: 100, PPID: 2, Comm: "new"})

	flushPendingExits(pt)

	node, err := pt.GetProcessNode(100)
	require.NoError(t, err)
	require.NotNil(t, node, "the new process's node must survive a pending exit that had no node of its own")
	assert.Equal(t, "new", node.Comm)
}

// THE TRAP. Dropping the pending-exit entry alone — delete(pt.pendingExits, pid)
// — makes both tests above pass while leaving the dead process's children linked
// to the recycled pid, so the new process silently inherits them. That is a
// quieter corruption than the one being fixed: the tree now claims an unrelated
// live process is the parent of another process's children, and every alert built
// from that branch inherits the lie.
//
// Retiring the predecessor properly reparents the children away first. This test
// exists so that simplification cannot be made without a test going red.
func TestPidReuse_ForkAfterExit_DoesNotInheritDeadChildren(t *testing.T) {
	pt := newReuseTestCreator(t)

	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ForkEvent, PID: 100, PPID: 1, Comm: "old-parent"})
	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ForkEvent, PID: 101, PPID: 100, Comm: "old-child"})
	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ExitEvent, PID: 100, Comm: "exit", Timestamp: time.Now()})

	// The kernel recycles pid 100 for a process unrelated to that child.
	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ForkEvent, PID: 100, PPID: 2, Comm: "new"})

	node, err := pt.GetProcessNode(100)
	require.NoError(t, err)
	require.NotNil(t, node)
	assert.Equal(t, "new", node.Comm)
	assert.Empty(t, node.ChildrenMap,
		"the dead process's children must be reparented away, not inherited by the recycled pid")

	// The child must survive — reparented, not deleted along with its parent.
	child, err := pt.GetProcessNode(101)
	require.NoError(t, err)
	require.NotNil(t, child, "the child must survive its parent's retirement")
	assert.NotEqual(t, uint32(100), child.PPID, "the child must no longer point at the recycled pid")
}

// BUG 2b — a recycle the fork/exec guard cannot see, because no fork event was
// observed for the new incarnation: the scan discovered it instead. The guard
// here is purely temporal — a node whose recorded creation postdates the exit
// event's arrival cannot be the process that exit was for. Both values are
// boot-domain, so no btime skew is involved.
func TestPidReuse_DelayedExit_SkipsNodeCreatedAfterExitArrival(t *testing.T) {
	pt := newReuseTestCreator(t)
	fakeNow := uint64(1_000_000_000_000) // 1000s after boot
	pt.nowBootNs = func() uint64 { return fakeNow }

	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ProcfsEvent, PID: 100, PPID: 1, Comm: "old",
		StartTimeNs: 900_000_000_000})
	// The exit arrives at 1000s.
	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ExitEvent, PID: 100, Comm: "exit", Timestamp: time.Now()})

	// Recycled, and rediscovered by the scan at 1010s — after the exit arrived.
	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ProcfsEvent, PID: 100, PPID: 2, Comm: "new",
		StartTimeNs: 1_010_000_000_000})

	pt.mutex.Lock()
	pt.exitByPid(100)
	pt.mutex.Unlock()

	node, err := pt.GetProcessNode(100)
	require.NoError(t, err)
	require.NotNil(t, node, "a node provably newer than the exit must survive")
	assert.Equal(t, "new", node.Comm)

	pt.mutex.RLock()
	_, stillPending := pt.pendingExits[100]
	pt.mutex.RUnlock()
	assert.False(t, stillPending, "the stale pending exit is consumed, not retried forever")
}

// The same guarantee, but reaching layer 2 rather than layer 3.
//
// The test above discovers the successor with a procfs event on a pid the side map
// already has a value for, so the start-time-change rebuild fires first, tears the
// node down and consumes the pending entry — exitByPid then takes its
// pending == nil early return and layer 2's comparison is never evaluated. That
// makes it a layer 3 test wearing layer 2's name: deleting layer 2 entirely leaves
// it green.
//
// Here the predecessor has NO side-map entry (fork only, with the on-demand read
// neutralised), so the rebuild declines — it requires a non-zero prior value — and
// the procfs event merely records the successor's start time. exitByPid therefore
// reaches layer 2 with a live pending entry, which is the branch under test.
func TestPidReuse_DelayedExit_LayerTwoKeepsNewerNodeWithoutRebuild(t *testing.T) {
	pt := newReuseTestCreator(t)
	pt.nowBootNs = func() uint64 { return 1_000_000_000_000 } // exit arrives at 1000s

	// Predecessor known only from a fork, so pidStartTimeNs[100] stays unset.
	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ForkEvent, PID: 100, PPID: 1, Comm: "old"})
	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ExitEvent, PID: 100, Comm: "exit", Timestamp: time.Now()})

	pt.mutex.RLock()
	prev := pt.pidStartTimeNs[100]
	pt.mutex.RUnlock()
	require.Zero(t, prev, "precondition: no prior start time, so the L3 rebuild must decline")

	// The scan sees the successor at 1010s — after the exit arrived.
	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ProcfsEvent, PID: 100, PPID: 2, Comm: "new",
		StartTimeNs: 1_010_000_000_000})

	pt.mutex.RLock()
	_, stillPendingBefore := pt.pendingExits[100]
	pt.mutex.RUnlock()
	require.True(t, stillPendingBefore, "precondition: the pending exit must still be armed, or L2 is not reached")

	pt.mutex.Lock()
	pt.exitByPid(100)
	pt.mutex.Unlock()

	node, err := pt.GetProcessNode(100)
	require.NoError(t, err)
	require.NotNil(t, node, "L2 must keep a node whose recorded creation postdates the exit's arrival")

	pt.mutex.RLock()
	_, stillPending := pt.pendingExits[100]
	pt.mutex.RUnlock()
	assert.False(t, stillPending, "L2 consumes the stale pending entry rather than retrying forever")
}

// Layer 1 applies to exec, not only fork. An exec proves a live process holds the
// pid just as a fork does, and while exec already overwrites comm/cmdline/path,
// the predecessor's delayed exit would still delete this live node and its
// children would still be inherited.
//
// Ordering matters here: the exec must arrive AFTER the exit, otherwise the guard
// is a no-op and the test proves nothing.
func TestPidReuse_ExecAfterExit_RetiresPredecessor(t *testing.T) {
	pt := newReuseTestCreator(t)

	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ForkEvent, PID: 100, PPID: 1, Comm: "old-parent"})
	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ForkEvent, PID: 101, PPID: 100, Comm: "old-child"})
	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ExitEvent, PID: 100, Comm: "exit", Timestamp: time.Now()})

	// The pid is recycled and the successor is first seen execing.
	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ExecEvent, PID: 100, PPID: 2, Comm: "new",
		Cmdline: "new --serve", Path: "/usr/bin/new"})

	pt.mutex.RLock()
	_, stillPending := pt.pendingExits[100]
	pt.mutex.RUnlock()
	assert.False(t, stillPending, "the exec must disarm the predecessor's delayed deletion")

	node, err := pt.GetProcessNode(100)
	require.NoError(t, err)
	require.NotNil(t, node)
	assert.Equal(t, "new", node.Comm)
	assert.Empty(t, node.ChildrenMap, "the dead process's children must not be inherited by the exec'd successor")

	// The predecessor's delayed exit must no longer be able to delete this node.
	flushPendingExits(pt)

	node, err = pt.GetProcessNode(100)
	require.NoError(t, err)
	require.NotNil(t, node, "the live successor's node must survive the predecessor's cleanup")
}

// Unknown start time means exactly today's behaviour. The guard must never keep a
// node it cannot prove is newer, so this population — nodes with no recorded
// creation time — falls through to deletion rather than being covered by a guess.
func TestPidReuse_DelayedExit_UnknownStartTimeStillDeletes(t *testing.T) {
	pt := newReuseTestCreator(t)
	pt.nowBootNs = func() uint64 { return 1_000_000_000_000 }

	// Fork only: no procfs event, and readStartTime is neutralised, so the side
	// map has no entry for this pid.
	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ForkEvent, PID: 100, PPID: 1, Comm: "old"})
	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ExitEvent, PID: 100, Comm: "exit", Timestamp: time.Now()})

	pt.mutex.Lock()
	pt.exitByPid(100)
	pt.mutex.Unlock()

	node, err := pt.GetProcessNode(100)
	require.NoError(t, err)
	assert.Nil(t, node, "no identity data means conservative deletion, byte-for-byte today's logic")
}

// The mirror of the guard: an exit that arrives AFTER the node was recorded — the
// ordinary, non-recycled case — must still delete. This is the assertion that
// stops the guard being written with the comparison inverted, which would leak
// every exited process's node forever.
func TestPidReuse_DelayedExit_NormalExitStillDeletes(t *testing.T) {
	pt := newReuseTestCreator(t)
	pt.nowBootNs = func() uint64 { return 1_000_000_000_000 } // exit arrives at 1000s

	// Node recorded at 900s, comfortably before the exit arrived.
	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ProcfsEvent, PID: 100, PPID: 1, Comm: "app",
		StartTimeNs: 900_000_000_000})
	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ExitEvent, PID: 100, Comm: "exit", Timestamp: time.Now()})

	pt.mutex.Lock()
	pt.exitByPid(100)
	pt.mutex.Unlock()

	node, err := pt.GetProcessNode(100)
	require.NoError(t, err)
	assert.Nil(t, node, "an ordinary exit must still remove its own process's node")
}

// BUG 1b — a recycle seen only through the procfs scan merges the two
// incarnations. handleProcfsEvent overwrites non-empty event fields but performs
// no identity comparison, so stale fields the new process does not have — Cwd
// here — survive from the dead one.
func TestPidReuse_ProcfsStartTimeChange_RebuildsNode(t *testing.T) {
	pt := newReuseTestCreator(t)

	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ProcfsEvent, PID: 100, PPID: 1,
		Comm: "malware", Cmdline: "malware --evil", Cwd: "/tmp/.hidden", StartTimeNs: 900_000_000_000})

	// Recycled: same pid, a different program, no Cwd readable yet.
	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ProcfsEvent, PID: 100, PPID: 2,
		Comm: "worker", Cmdline: "worker --queue=q1", StartTimeNs: 1_010_000_000_000})

	node, err := pt.GetProcessNode(100)
	require.NoError(t, err)
	require.NotNil(t, node)
	assert.Equal(t, "worker", node.Comm)
	assert.Equal(t, "worker --queue=q1", node.Cmdline)
	assert.Empty(t, node.Cwd, "stale Cwd from the dead incarnation must not survive the rebuild")
	assert.Equal(t, uint64(1_010_000_000_000), pt.GetProcessBootTimeNs(100))
}

// Same start time means the same process, so today's merge semantics must be
// left exactly as they are: fields refreshed, nothing torn down, children kept.
// This is the control for the test above — it must pass before and after the fix.
func TestPidReuse_ProcfsSameStartTime_MergesAsToday(t *testing.T) {
	pt := newReuseTestCreator(t)

	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ProcfsEvent, PID: 100, PPID: 1, Comm: "app",
		StartTimeNs: 900_000_000_000})
	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ForkEvent, PID: 101, PPID: 100, Comm: "child"})
	pt.FeedEvent(conversion.ProcessEvent{Type: conversion.ProcfsEvent, PID: 100, PPID: 1, Comm: "app",
		Cwd: "/srv", StartTimeNs: 900_000_000_000})

	node, err := pt.GetProcessNode(100)
	require.NoError(t, err)
	require.NotNil(t, node)
	assert.Equal(t, "/srv", node.Cwd)
	assert.Len(t, node.ChildrenMap, 1, "children survive a same-incarnation refresh")
}
