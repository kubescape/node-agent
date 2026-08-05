package processtreecreator

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSpinningExitManagerCreator builds a creator whose cleanup loop re-evaluates
// its select on a sub-millisecond tick. The stock helper's 30-second interval
// leaves the loop parked inside one select for the whole test, so the window in
// which the lifecycle fields are touched concurrently is practically
// unobservable.
func newSpinningExitManagerCreator() *processTreeCreatorImpl {
	pt := createTestProcessTreeCreator()
	pt.pidStartTimeNs = make(map[uint32]uint64)
	pt.config.ExitCleanup.CleanupInterval = 100 * time.Microsecond
	pt.config.ExitCleanup.CleanupDelay = time.Hour

	return pt
}

// The cleanup loop used to read pt.exitCleanupStopChan directly in its select
// while stopExitManager wrote to the same field, neither side synchronised. That
// single site was the whole of SUB-7847: all seven race reports in this package's
// -race baseline were this one field pair. The loop now takes the channel as an
// argument, so this test is the regression guard for that.
// NOTE: the race detector is this test's real assertion, and the pull-request
// pipeline does not run it (CGO_ENABLED: 0 — SUB-7848). The lifecycle assertion
// below keeps the test from being entirely vacuous there, but race evidence for
// this package has to come from a local -race run.
func TestExitManager_StopIsRaceFreeAgainstCleanupLoop(t *testing.T) {
	for i := 0; i < 50; i++ {
		pt := newSpinningExitManagerCreator()
		pt.Start()
		// Let the loop reach its select and start cycling through iterations.
		time.Sleep(2 * time.Millisecond)
		pt.Stop()
		require.Nil(t, pt.exitCleanupStopChan, "Stop must leave the manager in the stopped state")
	}
}

// Two concurrent Stop() calls used to be able to both pass the nil check and both
// reach the select's default branch, so both called close() on the same channel
// and the second panicked with "close of closed channel". The check and the close
// have to be one atomic transition, which is what the lifecycle mutex makes them.
func TestExitManager_ConcurrentStopDoesNotPanic(t *testing.T) {
	for i := 0; i < 200; i++ {
		pt := newSpinningExitManagerCreator()
		pt.Start()

		var wg sync.WaitGroup
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				pt.Stop()
			}()
		}
		wg.Wait()
	}
}

// After Stop() the cleanup goroutine must actually exit — not merely be signalled.
// This used to be decided by the race: a loop that read the nilled field rather
// than the closed channel blocked forever on a nil-channel receive, killing that
// select arm, so the loop kept ticking and mutating the tree for the lifetime of
// the process. The loop now holds its own channel reference and always observes
// the close.
//
// What this test does NOT claim is that cleanup stops instantly; see the comment
// at the settle window below.
func TestExitManager_StopHaltsCleanupLoop(t *testing.T) {
	pt := newSpinningExitManagerCreator()
	// Every pending exit is immediately due, so one tick drains it.
	pt.config.ExitCleanup.CleanupDelay = 0

	pt.Start()

	// Establish that the loop is live: a pending exit gets drained promptly.
	pt.mutex.Lock()
	pt.processMap.Set(100, createTestProcess(100, 1, "before-stop"))
	pt.pendingExits[100] = &pendingExit{PID: 100, Timestamp: time.Now()}
	pt.mutex.Unlock()

	require.Eventually(t, func() bool {
		pt.mutex.RLock()
		defer pt.mutex.RUnlock()
		_, stillPending := pt.pendingExits[100]
		return !stillPending
	}, 2*time.Second, time.Millisecond, "a running loop should drain a due pending exit")

	pt.Stop()

	// Let the loop observe the closed channel and return before seeding the
	// sentinel. Closing does not preempt an in-flight iteration, and when both
	// select arms are ready the runtime picks between them at random — so a
	// ticker this hot can win several rounds, and a cleanup pass or two after
	// Stop() is expected rather than a leak. What must not happen is cleanup
	// continuing indefinitely, which is what the sentinel below measures.
	time.Sleep(20 * time.Millisecond)

	// With the loop gone, a newly due pending exit must never be drained.
	pt.mutex.Lock()
	pt.processMap.Set(200, createTestProcess(200, 1, "after-stop"))
	pt.pendingExits[200] = &pendingExit{PID: 200, Timestamp: time.Now()}
	pt.mutex.Unlock()

	// ~500 tick intervals: ample for a surviving loop to reveal itself.
	time.Sleep(50 * time.Millisecond)

	pt.mutex.RLock()
	_, stillPending := pt.pendingExits[200]
	pt.mutex.RUnlock()
	assert.True(t, stillPending, "cleanup ran after Stop: the loop goroutine leaked")
}

// The stopped state is signalled by a nil channel, and Start() must be able to
// bring the manager back up — the behaviour TestExitManager_StartStop and
// TestStartStop pin. Preserved deliberately: the fix removes the race, not the
// lifecycle contract.
func TestExitManager_RestartAfterStop(t *testing.T) {
	pt := newSpinningExitManagerCreator()

	pt.Start()
	require.NotNil(t, pt.exitCleanupStopChan, "Start must arm the stop channel")

	pt.Stop()
	require.Nil(t, pt.exitCleanupStopChan, "Stop must leave the manager in the restartable nil state")

	pt.Start()
	require.NotNil(t, pt.exitCleanupStopChan, "the exit manager must be restartable after Stop")

	pt.Stop()
	require.Nil(t, pt.exitCleanupStopChan)
}
