package containerprofilemanager

import (
	"sync"
	"testing"
	"time"

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
