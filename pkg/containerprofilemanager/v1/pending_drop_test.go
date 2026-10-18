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
	return &ContainerEntry{data: &containerData{}}
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
