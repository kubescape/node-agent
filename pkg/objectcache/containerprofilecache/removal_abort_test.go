package containerprofilecache

import (
	"context"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A container removed before its shared data exists must abort its pending
// registration right away instead of waiting out the 10-minute timeout.
func TestContainerCallback_RemovalAbortsPendingRegistration(t *testing.T) {
	c, _ := newTestCache(t, &fakeProfileClient{})
	container := eventContainer("short-lived")

	c.ContainerCallback(containercollection.PubSubEvent{Type: containercollection.EventTypeAddContainer, Container: container})
	require.Equal(t, 1, c.pendingAdds.Len("short-lived"), "the add callback must track the registration synchronously")

	c.ContainerCallback(containercollection.PubSubEvent{Type: containercollection.EventTypeRemoveContainer, Container: container})
	assert.Zero(t, c.pendingAdds.Len("short-lived"))

	// The registration goroutine holds the container lock while it waits;
	// taking the lock proves the aborted wait returned.
	acquired := make(chan struct{})
	go func() {
		c.containerLocks.WithLock("short-lived", func() {})
		close(acquired)
	}()
	select {
	case <-acquired:
	case <-time.After(2 * time.Second):
		t.Fatal("removal did not abort the pending registration")
	}
}

// Only a removal downgrades the failure; a live container whose shared data
// never arrives stays an error.
func TestAddContainer_FailureClassification(t *testing.T) {
	c, _ := newTestCache(t, &fakeProfileClient{})

	t.Run("removed while waiting for shared data", func(t *testing.T) {
		parent, release := c.pendingAdds.Track("removed")
		defer release()
		ctx, cancel := context.WithTimeout(parent, time.Minute)
		defer cancel()
		time.AfterFunc(20*time.Millisecond, func() { c.pendingAdds.Cancel("removed") })

		require.Error(t, c.addContainer(eventContainer("removed"), ctx))
		assert.True(t, utils.RemovedDuringAdd(ctx))
	})

	t.Run("live container without shared data", func(t *testing.T) {
		parent, release := c.pendingAdds.Track("live")
		defer release()
		ctx, cancel := context.WithTimeout(parent, 50*time.Millisecond)
		defer cancel()

		require.Error(t, c.addContainer(eventContainer("live"), ctx))
		assert.False(t, utils.RemovedDuringAdd(ctx))
	})
}
