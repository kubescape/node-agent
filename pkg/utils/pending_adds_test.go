package utils

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPendingAdds_CancelAbortsTrackedRegistrations(t *testing.T) {
	var p PendingAdds
	first, releaseFirst := p.Track("c1")
	defer releaseFirst()
	second, releaseSecond := p.Track("c1")
	defer releaseSecond()
	other, releaseOther := p.Track("c2")
	defer releaseOther()

	child, cancel := context.WithTimeout(first, time.Hour)
	defer cancel()

	p.Cancel("c1")

	require.ErrorIs(t, first.Err(), context.Canceled)
	assert.True(t, RemovedDuringAdd(first))
	assert.True(t, RemovedDuringAdd(second))
	assert.True(t, RemovedDuringAdd(child), "a timeout context derived from the tracked one must inherit the removal cause")
	assert.NoError(t, other.Err(), "other containers must not be affected")
	assert.Zero(t, p.Len("c1"))
	assert.Equal(t, 1, p.Len("c2"))
}

func TestPendingAdds_ReadmissionAfterCancelIsNotAborted(t *testing.T) {
	var p PendingAdds
	_, releaseOld := p.Track("c1")
	p.Cancel("c1")
	releaseOld()

	readmitted, release := p.Track("c1")
	defer release()
	assert.NoError(t, readmitted.Err())
	assert.Equal(t, 1, p.Len("c1"))
}

func TestPendingAdds_ReleaseKeepsCauseAndUntracks(t *testing.T) {
	var p PendingAdds
	ctx, release := p.Track("c1")
	p.Cancel("c1")
	release()
	assert.True(t, RemovedDuringAdd(ctx), "release after removal must not overwrite the cause")

	ctx, release = p.Track("c1")
	release()
	assert.Zero(t, p.Len("c1"))
	assert.False(t, RemovedDuringAdd(ctx), "a settled registration is not a removal")
	p.Cancel("c1") // no tracked registration: no-op
}

func TestRemovedDuringAdd_OnlyRemovalCounts(t *testing.T) {
	var p PendingAdds
	parent, release := p.Track("c1")
	defer release()
	ctx, cancel := context.WithTimeout(parent, time.Millisecond)
	defer cancel()
	<-ctx.Done()
	assert.False(t, RemovedDuringAdd(ctx), "a deadline for a live container must stay an error")
	assert.False(t, RemovedDuringAdd(context.Background()), "a failure without cancellation must stay an error")
}
