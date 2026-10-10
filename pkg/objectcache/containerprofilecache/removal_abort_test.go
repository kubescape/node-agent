package containerprofilecache

import (
	"context"
	"sync"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// waitSignalK8sCache closes waiting on the first shared-data lookup.
// The cache does that lookup under the container lock.
type waitSignalK8sCache struct {
	*objectcache.K8sObjectCacheMock
	once    sync.Once
	waiting chan struct{}
}

func (k *waitSignalK8sCache) GetSharedContainerData(containerID string) *objectcache.WatchedContainerData {
	k.once.Do(func() { close(k.waiting) })
	return k.K8sObjectCacheMock.GetSharedContainerData(containerID)
}

// Removal before shared data exists aborts the registration at once.
func TestContainerCallback_RemovalAbortsPendingRegistration(t *testing.T) {
	k8s := &waitSignalK8sCache{K8sObjectCacheMock: &objectcache.K8sObjectCacheMock{}, waiting: make(chan struct{})}
	c := NewContainerProfileCache(config.Config{ProfilesCacheRefreshRate: 30 * time.Second}, &fakeProfileClient{}, k8s, nil)
	container := eventContainer("short-lived")

	c.ContainerCallback(containercollection.PubSubEvent{Type: containercollection.EventTypeAddContainer, Container: container})
	select {
	case <-k8s.waiting:
	case <-time.After(2 * time.Second):
		t.Fatal("registration never started waiting for shared data")
	}

	c.ContainerCallback(containercollection.PubSubEvent{Type: containercollection.EventTypeRemoveContainer, Container: container})

	// The wait holds the container lock.
	// Taking it proves the aborted wait returned.
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

// Only a removal downgrades the failure.
// Live container at the deadline: still an error.
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
