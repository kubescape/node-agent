package containerprofilemanager

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/hostidentity"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/seccompmanager"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newPendingDropManager() *ContainerProfileManager {
	return &ContainerProfileManager{containers: map[string]*ContainerEntry{}}
}

func newPendingEntry() *ContainerEntry {
	return &ContainerEntry{data: &containerData{}, ready: make(chan struct{})}
}

func dropped(e *ContainerEntry) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.data.droppedEvents
}

func TestReportDroppedEvent_BeforeRegistrationIsAppliedOnRegistration(t *testing.T) {
	cpm := newPendingDropManager()
	cpm.ReportDroppedEvent("c1")
	cpm.ReportDroppedEvent("c1") // repeated drains must not lose or duplicate the marker
	require.Len(t, cpm.pendingDrops, 1)

	entry := newPendingEntry()
	require.True(t, cpm.addContainerEntryIfAbsent("c1", entry))

	assert.True(t, dropped(entry))
	assert.Empty(t, cpm.pendingDrops, "marker is consumed once applied")

	// A later replayed registration of another entry for the same ID is not marked again.
	other := newPendingEntry()
	assert.False(t, cpm.addContainerEntryIfAbsent("c1", other))
	assert.False(t, dropped(other))
}

func TestReportDroppedEvent_AfterRegistration(t *testing.T) {
	cpm := newPendingDropManager()
	entry := newPendingEntry()
	require.True(t, cpm.addContainerEntryIfAbsent("c1", entry))
	require.False(t, dropped(entry), "registration alone must not mark a container partial")

	cpm.ReportDroppedEvent("c1")

	assert.True(t, dropped(entry))
	assert.Empty(t, cpm.pendingDrops)
}

func TestReportDroppedEvent_PendingMarkerIsPerContainer(t *testing.T) {
	cpm := newPendingDropManager()
	cpm.ReportDroppedEvent("affected")

	unaffected := newPendingEntry()
	require.True(t, cpm.addContainerEntryIfAbsent("unaffected", unaffected))
	assert.False(t, dropped(unaffected))
	assert.Contains(t, cpm.pendingDrops, "affected", "other registrations leave the marker alone")

	affected := newPendingEntry()
	require.True(t, cpm.addContainerEntryIfAbsent("affected", affected))
	assert.True(t, dropped(affected))
	assert.False(t, dropped(unaffected))
}

func TestReportDroppedEvent_PendingMarkersAreBounded(t *testing.T) {
	cpm := newPendingDropManager()
	for i := range maxPendingDrops + 10 {
		cpm.ReportDroppedEvent("c" + string(rune('a'+i%26)) + time.Duration(i).String())
	}
	assert.LessOrEqual(t, len(cpm.pendingDrops), maxPendingDrops)

	// Expired markers are pruned to make room.
	for id := range cpm.pendingDrops {
		cpm.pendingDrops[id] = time.Now().Add(-2 * MaxWaitForSharedContainerData)
	}
	cpm.ReportDroppedEvent("fresh")
	assert.Contains(t, cpm.pendingDrops, "fresh")
}

// Drops racing with registration must never be lost, whichever side wins.
func TestReportDroppedEvent_ConcurrentWithRegistration(t *testing.T) {
	for range 200 {
		cpm := newPendingDropManager()
		entry := newPendingEntry()
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); <-start; cpm.ReportDroppedEvent("c1") }()
		go func() { defer wg.Done(); <-start; cpm.addContainerEntryIfAbsent("c1", entry) }()
		close(start)
		wg.Wait()

		require.True(t, dropped(entry))
		require.Empty(t, cpm.pendingDrops)
	}
}

func TestReportDroppedEvent_EmptyContainerIDCreatesNoPendingMarker(t *testing.T) {
	cpm := newPendingDropManager()
	registered := newPendingEntry()
	require.True(t, cpm.addContainerEntryIfAbsent("c1", registered))

	cpm.ReportDroppedEvent("")

	assert.Empty(t, cpm.pendingDrops, "an unattributed drop has no profile to mark")
	assert.False(t, dropped(registered), "an unattributed drop must not mark another container")

	// Attributed drops are unchanged: registered containers are marked, unregistered ones get a marker.
	cpm.ReportDroppedEvent("c1")
	cpm.ReportDroppedEvent("c2")
	assert.True(t, dropped(registered))
	assert.Contains(t, cpm.pendingDrops, "c2")
	assert.NotContains(t, cpm.pendingDrops, "")
}

// A registration that fails after it consumed a pending marker or recorded a drop is
// abandoned and may be replaced by a replayed registration with a fresh entry; the drop
// must follow the container to that replacement.
func TestAbandonEntry_CarriesDropToReplacementEntry(t *testing.T) {
	for _, tc := range []struct {
		name string
		drop func(cpm *ContainerProfileManager) // runs around the first entry's registration
	}{
		{"marker applied at insertion", func(cpm *ContainerProfileManager) { cpm.ReportDroppedEvent("c1") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cpm := newPendingDropManager()
			tc.drop(cpm)
			first := newPendingEntry()
			require.True(t, cpm.addContainerEntryIfAbsent("c1", first))
			require.True(t, dropped(first))

			cpm.abandonEntry("c1", first)
			assert.Nil(t, first.data, "an abandoned entry no longer accepts reports")

			replacement := newPendingEntry()
			require.True(t, cpm.addContainerEntryIfAbsent("c1", replacement))
			assert.True(t, dropped(replacement))
			assert.Empty(t, cpm.pendingDrops)
		})
	}

	t.Run("drop recorded on the live entry", func(t *testing.T) {
		cpm := newPendingDropManager()
		first := newPendingEntry()
		require.True(t, cpm.addContainerEntryIfAbsent("c1", first))
		cpm.ReportDroppedEvent("c1")

		cpm.abandonEntry("c1", first)

		replacement := newPendingEntry()
		require.True(t, cpm.addContainerEntryIfAbsent("c1", replacement))
		assert.True(t, dropped(replacement))
	})

	t.Run("replacement already registered", func(t *testing.T) {
		cpm := newPendingDropManager()
		first := newPendingEntry()
		require.True(t, cpm.addContainerEntryIfAbsent("c1", first))
		cpm.ReportDroppedEvent("c1")
		cpm.mustRemove(t, "c1")
		replacement := newPendingEntry()
		require.True(t, cpm.addContainerEntryIfAbsent("c1", replacement))

		// The first attempt's cleanup runs late, after the replacement is installed: it must
		// neither untrack the replacement nor carry the drop over (it is no longer current).
		cpm.abandonEntry("c1", first)

		got, ok := cpm.getContainerEntry("c1")
		require.True(t, ok)
		assert.Same(t, replacement, got)
		assert.False(t, dropped(replacement))
	})

	t.Run("no drop is not invented", func(t *testing.T) {
		cpm := newPendingDropManager()
		first := newPendingEntry()
		require.True(t, cpm.addContainerEntryIfAbsent("c1", first))

		cpm.abandonEntry("c1", first)

		replacement := newPendingEntry()
		require.True(t, cpm.addContainerEntryIfAbsent("c1", replacement))
		assert.False(t, dropped(replacement))
		assert.Empty(t, cpm.pendingDrops)
	})

	t.Run("report racing the abandon is not lost", func(t *testing.T) {
		for range 200 {
			cpm := newPendingDropManager()
			first := newPendingEntry()
			require.True(t, cpm.addContainerEntryIfAbsent("c1", first))
			start := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); <-start; cpm.ReportDroppedEvent("c1") }()
			go func() { defer wg.Done(); <-start; cpm.abandonEntry("c1", first) }()
			close(start)
			wg.Wait()

			replacement := newPendingEntry()
			require.True(t, cpm.addContainerEntryIfAbsent("c1", replacement))
			require.True(t, dropped(replacement))
		}
	})
}

func (cpm *ContainerProfileManager) mustRemove(t *testing.T, containerID string) {
	t.Helper()
	_, ok := cpm.removeContainerEntry(containerID)
	require.True(t, ok)
}

// When the pending set is full the marker for a new container cannot be stored. A container
// registering afterwards must still not come out complete, the set must stay bounded, and
// containers registered long after the overflow are unaffected.
func TestReportDroppedEvent_OverflowMarksLaterRegistrationPartial(t *testing.T) {
	cpm := newPendingDropManager()
	for i := range maxPendingDrops {
		cpm.ReportDroppedEvent(fmt.Sprintf("fill-%d", i))
	}
	require.Len(t, cpm.pendingDrops, maxPendingDrops)

	cpm.ReportDroppedEvent("overflowed")
	assert.Len(t, cpm.pendingDrops, maxPendingDrops, "the bound holds")
	assert.NotContains(t, cpm.pendingDrops, "overflowed")

	overflowed := newPendingEntry()
	require.True(t, cpm.addContainerEntryIfAbsent("overflowed", overflowed))
	assert.True(t, dropped(overflowed), "a lost marker must not yield a Complete profile")

	// Normal markers are still consumed per container.
	stored := newPendingEntry()
	require.True(t, cpm.addContainerEntryIfAbsent("fill-0", stored))
	assert.True(t, dropped(stored))
	assert.Len(t, cpm.pendingDrops, maxPendingDrops-1)

	// Already registered containers keep being marked directly.
	registered := newPendingEntry()
	require.True(t, cpm.addContainerEntryIfAbsent("registered", registered))
	cpm.ReportDroppedEvent("registered")
	assert.True(t, dropped(registered))

	// Once the registration window of the overflow has passed, the fallback no longer applies.
	cpm.containersMu.Lock()
	cpm.pendingDropsOverflowAt = time.Now().Add(-2 * MaxWaitForSharedContainerData)
	cpm.containersMu.Unlock()
	late := newPendingEntry()
	require.True(t, cpm.addContainerEntryIfAbsent("late", late))
	assert.False(t, dropped(late), "unrelated profiles are not marked partial after the window")
}

func TestReportDroppedEvent_NoOverflowLeavesRegistrationComplete(t *testing.T) {
	cpm := newPendingDropManager()
	for i := range maxPendingDrops - 1 {
		cpm.ReportDroppedEvent(fmt.Sprintf("fill-%d", i))
	}
	entry := newPendingEntry()
	require.True(t, cpm.addContainerEntryIfAbsent("clean", entry))
	assert.False(t, dropped(entry), "below capacity, unrelated registrations are not marked")
}

// A registration that is inserted and then abandoned between ReportDroppedEvent's lookup and
// its pending-marker check must not swallow the drop: the marker is retained and applied to the
// next registration, whose profile is then saved as Partial.
func TestReportDroppedEvent_EntryInsertedThenAbandonedBetweenLookups(t *testing.T) {
	t.Setenv("QUEUE_DIR", t.TempDir())
	cpm, err := NewContainerProfileManager(context.Background(), config.Config{}, nil, nil,
		&storage.StorageHttpClientMock{}, nil, &seccompmanager.SeccompManagerMock{}, nil, nil, nil)
	require.NoError(t, err)
	t.Cleanup(cpm.Close)

	newEntry := func() (*ContainerEntry, *objectcache.WatchedContainerData) {
		watched := hostidentity.BuildHostWatchedContainerData("node-1")
		watched.ContainerID = "c1"
		watched.SetCompletionStatus(objectcache.WatchedContainerCompletionStatusFull)
		return &ContainerEntry{data: &containerData{watchedContainerData: watched}, ready: make(chan struct{})}, watched
	}
	entryA, _ := newEntry()

	var steps []string
	cpm.dropReportHook = func(step string) {
		steps = append(steps, step)
		switch len(steps) {
		case 1: // initial lookup missed: registration inserts A before the marker check
			require.True(t, cpm.addContainerEntryIfAbsent("c1", entryA))
		case 2: // the marker check saw A and declined: A's registration fails before the retry lookup
			cpm.abandonEntry("c1", entryA)
		}
	}

	cpm.ReportDroppedEvent("c1")

	require.Equal(t, []string{"lookup-miss", "record-declined", "lookup-miss"}, steps)
	require.False(t, dropped(entryA), "the drop was never applied to the abandoned entry")
	require.Contains(t, cpm.pendingDrops, "c1", "the drop is retained for the next registration")

	// Registration is retried and creates entry B.
	entryB, watchedB := newEntry()
	require.True(t, cpm.addContainerEntryIfAbsent("c1", entryB))
	assert.True(t, dropped(entryB))
	assert.Empty(t, cpm.pendingDrops, "the marker is consumed exactly once")

	container := hostContainerWithIdentity(newHostPseudoContainer(), watchedB, "kubescape")
	require.NoError(t, cpm.saveProfile(watchedB, container, true))
	assert.Equal(t, objectcache.WatchedContainerCompletionStatusPartial, watchedB.GetCompletionStatus())
}
