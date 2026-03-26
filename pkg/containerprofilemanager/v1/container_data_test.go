package containerprofilemanager

import (
	"testing"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/stretchr/testify/assert"
)

// TestIsEmpty_SyscallsOnlyDoesNotTriggerSave proves the fix for the CVE overwrite bug.
//
// Background: PR #745 added `cd.syscalls != nil` to isEmpty(), which caused
// syscall-only profile snapshots to be saved. These snapshots have opens=nil,
// so kubevuln finds 0 relevant CVEs and overwrites the filtered
// VulnerabilityManifest with 0 CVEs.
//
// The fix: remove `cd.syscalls != nil` from isEmpty(). Syscalls alone should
// NOT trigger a profile save, because kubevuln uses file opens (not syscalls)
// for relevancy matching. Saving a profile with only syscalls and no opens
// produces a 0-CVE scan that destroys existing results.
//
// Syscalls are still saved when other events (opens, execs, etc.) trigger a
// save, so no syscall data is lost.
func TestIsEmpty_SyscallsOnlyDoesNotTriggerSave(t *testing.T) {
	// Set up a container that has already been saved once (lastReported matches current).
	wcd := &objectcache.WatchedContainerData{}
	wcd.SetStatus(objectcache.WatchedContainerStatusReady)
	wcd.SetCompletionStatus(objectcache.WatchedContainerCompletionStatusFull)

	cd := &containerData{
		watchedContainerData:   wcd,
		lastReportedCompletion: string(objectcache.WatchedContainerCompletionStatusFull),
		lastReportedStatus:     string(objectcache.WatchedContainerStatusReady),
	}

	// Baseline: no events → isEmpty() is true (save skipped)
	assert.True(t, cd.isEmpty(), "should be empty when no events and status unchanged")

	// Simulate what happens after redis-server starts and runs for 30s:
	// The process continuously generates syscalls (read, write, epoll_wait, etc.)
	// but does NOT open any new files (libraries were loaded at startup).
	cd.syscalls = mapset.NewSet("read", "write", "epoll_wait", "clock_gettime")

	// With the fix: isEmpty() should return true — syscalls alone should NOT
	// trigger a save, because saving a syscalls-only profile causes kubevuln
	// to overwrite the filtered VM with 0 CVEs.
	assert.True(t, cd.isEmpty(),
		"syscalls-only data should NOT trigger a save (prevents 0-CVE overwrite)")
}

// TestIsEmpty_OpensStillTriggerSave verifies that file opens correctly trigger
// a save. This is the desired behavior — opens are what kubevuln uses for
// relevancy matching.
func TestIsEmpty_OpensStillTriggerSave(t *testing.T) {
	wcd := &objectcache.WatchedContainerData{}
	wcd.SetStatus(objectcache.WatchedContainerStatusReady)
	wcd.SetCompletionStatus(objectcache.WatchedContainerCompletionStatusFull)

	cd := &containerData{
		watchedContainerData:   wcd,
		lastReportedCompletion: string(objectcache.WatchedContainerCompletionStatusFull),
		lastReportedStatus:     string(objectcache.WatchedContainerStatusReady),
	}

	// File opens (e.g., redis-server loading shared libraries) → should trigger save
	opens := &maps.SafeMap[string, mapset.Set[string]]{}
	opens.Set("/usr/lib/x86_64-linux-gnu/libssl.so.3", mapset.NewSet("O_RDONLY"))
	cd.opens = opens

	assert.False(t, cd.isEmpty(), "opens should trigger a save")
}

// TestIsEmpty_SyscallsWithOpensTriggersSave verifies that when syscalls AND
// opens are both present, the save is triggered (as expected).
func TestIsEmpty_SyscallsWithOpensTriggersSave(t *testing.T) {
	wcd := &objectcache.WatchedContainerData{}
	wcd.SetStatus(objectcache.WatchedContainerStatusReady)
	wcd.SetCompletionStatus(objectcache.WatchedContainerCompletionStatusFull)

	cd := &containerData{
		watchedContainerData:   wcd,
		lastReportedCompletion: string(objectcache.WatchedContainerCompletionStatusFull),
		lastReportedStatus:     string(objectcache.WatchedContainerStatusReady),
	}

	// Both opens and syscalls present (e.g., right after redis-server loads libraries)
	opens := &maps.SafeMap[string, mapset.Set[string]]{}
	opens.Set("/usr/lib/x86_64-linux-gnu/libssl.so.3", mapset.NewSet("O_RDONLY"))
	cd.opens = opens
	cd.syscalls = mapset.NewSet("read", "write", "openat")

	assert.False(t, cd.isEmpty(), "opens+syscalls should trigger a save")

	// After save, emptyEvents() clears everything
	cd.emptyEvents()
	assert.True(t, cd.isEmpty(), "should be empty after emptyEvents()")

	// Now only syscalls accumulate (no new opens) — should NOT trigger save
	cd.syscalls = mapset.NewSet("read", "write", "epoll_wait")
	assert.True(t, cd.isEmpty(),
		"after a full save+clear, syscalls-only should not trigger another save")
}

// TestIsEmpty_StatusChangeTriggersFirstSave verifies that a status change
// (from "" to "Learning") correctly triggers the first profile save.
func TestIsEmpty_StatusChangeTriggersFirstSave(t *testing.T) {
	wcd := &objectcache.WatchedContainerData{}
	wcd.SetStatus(objectcache.WatchedContainerStatusReady)
	wcd.SetCompletionStatus(objectcache.WatchedContainerCompletionStatusFull)

	cd := &containerData{
		watchedContainerData:   wcd,
		lastReportedCompletion: "",
		lastReportedStatus:     "",
	}

	assert.False(t, cd.isEmpty(),
		"status mismatch should trigger save (first profile snapshot)")
}
