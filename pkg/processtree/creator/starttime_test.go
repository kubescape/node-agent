package processtreecreator

import (
	"os"
	"testing"
	"time"

	"github.com/prometheus/procfs"

	"github.com/kubescape/node-agent/pkg/config"
	processtreecreatorconfig "github.com/kubescape/node-agent/pkg/processtree/config"
	"github.com/kubescape/node-agent/pkg/processtree/conversion"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleProcfsEvent_RecordsStartTime(t *testing.T) {
	creator := NewProcessTreeCreator(&mockContainerProcessTree{}, config.Config{})
	wall := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
	creator.FeedEvent(conversion.ProcessEvent{
		Type: conversion.ProcfsEvent, Timestamp: time.Now(),
		PID: 100, PPID: 1, Comm: "nginx",
		StartTimeNs: 555_550_000_000, StartTimeWall: wall,
	})

	// Boot-ns identity: exposed via the accessor, sourced from the side map.
	assert.Equal(t, uint64(555_550_000_000), creator.GetProcessBootTimeNs(100))
	assert.Zero(t, creator.GetProcessBootTimeNs(999), "unknown pid reads as 0")

	// Wall-clock display value on the node.
	node, err := creator.GetProcessNode(100)
	require.NoError(t, err)
	require.NotNil(t, node)
	assert.Equal(t, wall, node.StartTime)
}

func TestExitByPid_DeletesStartTimeEntry(t *testing.T) {
	cfg := config.Config{}
	cfg.ExitCleanup = processtreecreatorconfig.ExitCleanupConfig{
		MaxPendingExits: 10, CleanupInterval: time.Hour, CleanupDelay: 0,
	}
	creator := NewProcessTreeCreator(&mockContainerProcessTree{}, cfg).(*processTreeCreatorImpl)
	creator.FeedEvent(conversion.ProcessEvent{
		Type: conversion.ProcfsEvent, PID: 100, PPID: 1, Comm: "nginx",
		StartTimeNs: 1_000_000_000,
	})
	require.Equal(t, uint64(1_000_000_000), creator.GetProcessBootTimeNs(100),
		"precondition: the side map must hold the entry before the exit")

	creator.FeedEvent(conversion.ProcessEvent{
		Type: conversion.ExitEvent, PID: 100, Comm: "exit", Timestamp: time.Now(),
	})
	creator.mutex.Lock()
	creator.exitByPid(100)
	creator.mutex.Unlock()

	assert.Zero(t, creator.GetProcessBootTimeNs(100), "side-map entry must die with the node")
}

func TestHandleForkEvent_ReadsStartTimeOnDemand(t *testing.T) {
	creator := NewProcessTreeCreator(&mockContainerProcessTree{}, config.Config{}).(*processTreeCreatorImpl)
	wall := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	reads := 0
	creator.readStartTime = func(pid uint32) (uint64, time.Time) {
		reads++
		require.Equal(t, uint32(100), pid)
		return 777_770_000_000, wall
	}

	creator.FeedEvent(conversion.ProcessEvent{Type: conversion.ForkEvent, PID: 100, PPID: 1, Comm: "curl"})
	assert.Equal(t, uint64(777_770_000_000), creator.GetProcessBootTimeNs(100),
		"a fork-created node must not wait up to a scan interval for its identity")
	node, err := creator.GetProcessNode(100)
	require.NoError(t, err)
	assert.Equal(t, wall, node.StartTime)
	assert.Equal(t, 1, reads)

	// Exec on the same node: creation time cannot change on exec — no re-read.
	creator.FeedEvent(conversion.ProcessEvent{Type: conversion.ExecEvent, PID: 100, PPID: 1, Comm: "curl", Cmdline: "curl -s"})
	assert.Equal(t, 1, reads, "one read per node creation, never per event")
}

func TestHandleExecEvent_ReadsStartTimeOnDemand(t *testing.T) {
	creator := NewProcessTreeCreator(&mockContainerProcessTree{}, config.Config{}).(*processTreeCreatorImpl)
	wall := time.Date(2026, 7, 29, 13, 0, 0, 0, time.UTC)
	creator.readStartTime = func(pid uint32) (uint64, time.Time) { return 888_880_000_000, wall }

	// An exec with no preceding fork event still creates the node, so it must
	// also acquire an identity rather than waiting for the next scan.
	creator.FeedEvent(conversion.ProcessEvent{Type: conversion.ExecEvent, PID: 200, PPID: 1, Comm: "sh"})
	assert.Equal(t, uint64(888_880_000_000), creator.GetProcessBootTimeNs(200))
	node, err := creator.GetProcessNode(200)
	require.NoError(t, err)
	assert.Equal(t, wall, node.StartTime)
}

func TestHandleForkEvent_ReadFailureLeavesZero(t *testing.T) {
	creator := NewProcessTreeCreator(&mockContainerProcessTree{}, config.Config{}).(*processTreeCreatorImpl)
	creator.readStartTime = func(pid uint32) (uint64, time.Time) { return 0, time.Time{} } // process already gone
	creator.FeedEvent(conversion.ProcessEvent{Type: conversion.ForkEvent, PID: 100, PPID: 1, Comm: "flash"})
	assert.Zero(t, creator.GetProcessBootTimeNs(100), "failure degrades to the pre-existing zero, never a guess")
}

// TestHandleForkEvent_IgnoresEventStartTimeNs pins the clock-domain boundary.
// convertForkEvent sets ProcessEvent.StartTimeNs from the event's wall-clock
// timestamp — epoch nanoseconds, not boot-relative, and stamping the fork rather
// than process creation. Letting that value into the side map would make identity
// comparisons wrong by decades while still compiling and still joining correctly
// within a single message. Only the procfs read may populate the side map.
func TestHandleForkEvent_IgnoresEventStartTimeNs(t *testing.T) {
	creator := NewProcessTreeCreator(&mockContainerProcessTree{}, config.Config{}).(*processTreeCreatorImpl)
	creator.readStartTime = func(pid uint32) (uint64, time.Time) { return 777_770_000_000, time.Time{} }

	const epochNs = uint64(1_753_876_800_000_000_000) // what convertForkEvent would supply
	creator.FeedEvent(conversion.ProcessEvent{
		Type: conversion.ForkEvent, PID: 100, PPID: 1, Comm: "curl", StartTimeNs: epochNs,
	})

	assert.Equal(t, uint64(777_770_000_000), creator.GetProcessBootTimeNs(100),
		"the side map must hold the procfs boot-relative read, not the event's epoch timestamp")
}

// TestHandleForkEvent_IgnoresEventStartTimeNs_OnReadFailure is the same boundary
// on the failure path: a failed read must leave zero, never fall back to the
// event's epoch timestamp.
func TestHandleForkEvent_IgnoresEventStartTimeNs_OnReadFailure(t *testing.T) {
	creator := NewProcessTreeCreator(&mockContainerProcessTree{}, config.Config{}).(*processTreeCreatorImpl)
	creator.readStartTime = func(pid uint32) (uint64, time.Time) { return 0, time.Time{} }

	creator.FeedEvent(conversion.ProcessEvent{
		Type: conversion.ForkEvent, PID: 100, PPID: 1, Comm: "curl",
		StartTimeNs: 1_753_876_800_000_000_000,
	})

	assert.Zero(t, creator.GetProcessBootTimeNs(100),
		"a failed read must degrade to zero, never to the event's epoch timestamp")
}

// TestExitByPid_DeletesStartTimeEntry_NodeAlreadyGone covers exitByPid's early
// return: the node is absent from processMap, but a stale side-map entry must
// still be reclaimed rather than leaking for the lifetime of the agent.
func TestExitByPid_DeletesStartTimeEntry_NodeAlreadyGone(t *testing.T) {
	cfg := config.Config{}
	cfg.ExitCleanup = processtreecreatorconfig.ExitCleanupConfig{
		MaxPendingExits: 10, CleanupInterval: time.Hour, CleanupDelay: 0,
	}
	creator := NewProcessTreeCreator(&mockContainerProcessTree{}, cfg).(*processTreeCreatorImpl)

	creator.mutex.Lock()
	creator.pidStartTimeNs[404] = 2_000_000_000 // entry with no corresponding node
	creator.exitByPid(404)
	creator.mutex.Unlock()

	assert.Zero(t, creator.GetProcessBootTimeNs(404),
		"the early-return branch must reclaim the side-map entry too")
}

// TestProcfsStartTimeReader_ReadsRealProcess covers newProcfsStartTimeReader
// itself. Every other test on the on-demand path injects a fake reader, so
// without this the real /proc parse and its tick->nanosecond conversion have no
// coverage at all: this package's nsPerTick could drift from the feeder's and
// the same process would get two identities an order of magnitude apart, each
// internally consistent.
//
// The conversion is pinned against an independently read field 22 times the
// contract's literal 10^7, so a drifted constant fails deterministically rather
// than only on machines whose uptime happens to make the error visible.
func TestProcfsStartTimeReader_ReadsRealProcess(t *testing.T) {
	read := newProcfsStartTimeReader()

	ns, wall := read(uint32(os.Getpid()))
	require.NotZero(t, ns, "the test's own process must be readable from /proc")

	p, err := procfs.NewProc(os.Getpid())
	require.NoError(t, err)
	stat, err := p.Stat()
	require.NoError(t, err)
	assert.Equal(t, stat.Starttime*10_000_000, ns,
		"conversion must be exactly field 22 ticks * 10^7 ns (USER_HZ=100)")

	assert.False(t, wall.IsZero(), "btime should be readable, so the display value should be set")
	assert.WithinDuration(t, time.Now(), wall, 5*time.Minute,
		"btime + boot-relative offset must reconstruct this process's actual start time")

	// A pid that cannot exist degrades to zeros rather than guessing.
	nsGone, wallGone := read(uint32(1 << 22))
	assert.Zero(t, nsGone, "an unreadable process must yield zero, never a guess")
	assert.True(t, wallGone.IsZero())
}

// TestHandleForkEvent_RecycledPidDoesNotInheritDeadProcessStartTime guards the
// case the start time exists to catch. A fork's pid is newborn by definition, so
// a surviving side-map entry can only mean the kernel recycled the pid.
//
// It is reachable with shipped defaults: exitCleanup.cleanupDelay is 5 minutes,
// so an exited process's tree node AND its side-map entry outlive it by that
// long. Without the guard the recycled pid reports the DEAD process's start
// time, and if the new process lives less than one 30s scan interval — the
// short-lived population the on-demand read was added for — the periodic scan
// never corrects it. That is worse than the zero it replaces: a consumer joining
// on (pid, startTime) concludes the two processes are one.
//
// Scoped to this package's side map only. This is NOT pid-reuse hardening: the
// shared tree node still carries the dead process's comm, cmdline and path.
func TestHandleForkEvent_RecycledPidDoesNotInheritDeadProcessStartTime(t *testing.T) {
	cfg := config.Config{}
	cfg.ExitCleanup = processtreecreatorconfig.ExitCleanupConfig{
		MaxPendingExits: 1000,
		CleanupInterval: 30 * time.Second,
		CleanupDelay:    5 * time.Minute, // shipped default
	}
	creator := NewProcessTreeCreator(&mockContainerProcessTree{}, cfg).(*processTreeCreatorImpl)

	const aStart = uint64(1_000_000_000) // process A, boot+1s
	const bStart = uint64(9_000_000_000) // process B, boot+9s
	aWall := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
	bWall := time.Date(2026, 7, 29, 10, 30, 0, 0, time.UTC)
	creator.readStartTime = func(pid uint32) (uint64, time.Time) { return bStart, bWall }

	// Process A on pid 4242, seen by the periodic scan.
	creator.FeedEvent(conversion.ProcessEvent{
		Type: conversion.ProcfsEvent, PID: 4242, PPID: 1, Comm: "victim",
		StartTimeNs: aStart, StartTimeWall: aWall,
	})
	require.Equal(t, aStart, creator.GetProcessBootTimeNs(4242))

	// A exits. Cleanup is delayed, so the node and the side-map entry survive.
	creator.FeedEvent(conversion.ProcessEvent{
		Type: conversion.ExitEvent, PID: 4242, Comm: "exit", Timestamp: time.Now(),
	})

	// The kernel recycles 4242 for process B; B's fork event arrives.
	creator.FeedEvent(conversion.ProcessEvent{
		Type: conversion.ForkEvent, PID: 4242, PPID: 1, Comm: "beacon",
	})

	assert.Equal(t, bStart, creator.GetProcessBootTimeNs(4242),
		"a newborn pid must get its OWN start time, not the dead process's")

	// The node is reused, so its display value must be restamped too. If only the
	// side map is cleared, the identity value and the value shown to a human
	// disagree for exactly the case this guard exists to handle.
	node, err := creator.GetProcessNode(4242)
	require.NoError(t, err)
	require.NotNil(t, node)
	assert.Equal(t, bWall, node.StartTime,
		"the reused node must not keep displaying the dead process's start time")
}

// TestHandleForkEvent_ReadsStartTimeWithoutHoldingTreeLock pins that the fork
// path's /proc read happens OUTSIDE pt.mutex.
//
// pt.mutex is the tree-wide write lock that every alert type contends on, and
// fork is the highest-volume event path on a node — thousands per second on a
// busy one. Since the recycled-pid guard drops any stale entry, every fork now
// performs a read, so holding the lock across it would serialise a file read
// into the hot path for the whole process tree.
//
// TryRLock rather than RLock: if the write lock were held, RLock from this same
// goroutine would deadlock and the test would hang instead of failing.
func TestHandleForkEvent_ReadsStartTimeWithoutHoldingTreeLock(t *testing.T) {
	creator := NewProcessTreeCreator(&mockContainerProcessTree{}, config.Config{}).(*processTreeCreatorImpl)

	readWasLockFree := false
	creator.readStartTime = func(pid uint32) (uint64, time.Time) {
		if creator.mutex.TryRLock() {
			readWasLockFree = true
			creator.mutex.RUnlock()
		}
		return 555_550_000_000, time.Time{}
	}

	creator.FeedEvent(conversion.ProcessEvent{Type: conversion.ForkEvent, PID: 100, PPID: 1, Comm: "curl"})

	assert.True(t, readWasLockFree,
		"the fork path's /proc read must not hold the tree-wide write lock")
	assert.Equal(t, uint64(555_550_000_000), creator.GetProcessBootTimeNs(100),
		"and the value must still be stored")
}

// A fork on an existing node does not always mean pid reuse — some other path
// may simply have created the node first. Wiping unconditionally destroys a
// good scan-recorded value whenever the on-demand read then fails, so the wipe
// is gated on there actually being a pending exit for the pid.
func TestHandleForkEvent_DoesNotWipeKnownStartTimeWithoutAPendingExit(t *testing.T) {
	cfg := config.Config{}
	cfg.ExitCleanup = processtreecreatorconfig.ExitCleanupConfig{
		MaxPendingExits: 1000, CleanupInterval: time.Hour, CleanupDelay: time.Minute,
	}
	creator := NewProcessTreeCreator(&mockContainerProcessTree{}, cfg).(*processTreeCreatorImpl)
	creator.readStartTime = func(pid uint32) (uint64, time.Time) { return 0, time.Time{} } // read fails

	wall := time.Date(2026, 8, 3, 9, 0, 0, 0, time.UTC)
	creator.FeedEvent(conversion.ProcessEvent{
		Type: conversion.ProcfsEvent, PID: 100, PPID: 1, Comm: "nginx",
		StartTimeNs: 1_000_000_000, StartTimeWall: wall,
	})
	require.Equal(t, uint64(1_000_000_000), creator.GetProcessBootTimeNs(100))

	// No exit for this pid, so the node is still nginx's — not a recycled pid.
	creator.FeedEvent(conversion.ProcessEvent{Type: conversion.ForkEvent, PID: 100, PPID: 1, Comm: "nginx"})

	assert.Equal(t, uint64(1_000_000_000), creator.GetProcessBootTimeNs(100),
		"a failed read must not destroy a value the scan already recorded")
	node, err := creator.GetProcessNode(100)
	require.NoError(t, err)
	assert.Equal(t, wall, node.StartTime, "nor the display value")
}
