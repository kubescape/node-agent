package containerprofilecache

import (
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/stretchr/testify/require"
)

func TestNamespaceCleanupDoesNotBlockUnrelatedContainers(t *testing.T) {
	cache, k8s := newTestCache(t, &fakeProfileClient{})
	cache.removalGrace = time.Millisecond
	// Model registration waiting on metadata while holding its per-container lock.
	blocked := cache.containerLocks.GetLock("blocked")
	blocked.Lock()
	defer blocked.Unlock()
	container := &containercollection.Container{}
	container.Runtime.ContainerID = "blocked"
	cache.ContainerCallback(containercollection.PubSubEvent{Type: containercollection.EventTypeRemoveContainer, Container: container})

	other := &containercollection.Container{}
	other.Runtime.ContainerID = "other"
	other.K8s.Namespace = "default"
	primeSharedData(t, k8s, "other", "wlid://cluster-test/namespace-default/deployment-nginx")
	// Keep exercising unrelated callbacks across the timer's firing window. A
	// blocked removal must never prevent either callback from returning.
	for range 5 {
		<-time.After(10 * time.Millisecond)
		done := make(chan struct{})
		go func() {
			cache.ContainerCallback(containercollection.PubSubEvent{Type: containercollection.EventTypeAddContainer, Container: other})
			cache.ContainerCallback(containercollection.PubSubEvent{Type: containercollection.EventTypeRemoveContainer, Container: other})
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("unrelated lifecycle callbacks blocked behind stalled registration")
		}
	}
}

func TestNamespaceCleanupRechecksReadmissionAfterWaiting(t *testing.T) {
	cache, k8s := newTestCache(t, &fakeProfileClient{})
	cache.removalGrace = time.Millisecond
	id := "readmitted-while-cleanup-waits"
	lock := cache.containerLocks.GetLock(id)
	lock.Lock()
	container := &containercollection.Container{}
	container.Runtime.ContainerID = id
	container.K8s.Namespace = "default"
	primeSharedData(t, k8s, id, "wlid://cluster-test/namespace-default/deployment-nginx")
	cache.entries.Set(id, &CachedContainerProfile{})
	cache.ContainerCallback(containercollection.PubSubEvent{Type: containercollection.EventTypeRemoveContainer, Container: container})
	<-time.After(20 * time.Millisecond)
	added := make(chan struct{})
	go func() {
		cache.ContainerCallback(containercollection.PubSubEvent{Type: containercollection.EventTypeAddContainer, Container: container})
		close(added)
	}()
	select {
	case <-added:
	case <-time.After(time.Second):
		lock.Unlock()
		t.Fatal("readmission blocked on cleanup's global lock")
	}
	lock.Unlock()
	require.Never(t, func() bool { _, ok := cache.entries.Load(id); return !ok }, 100*time.Millisecond, time.Millisecond)
}
