package containerprofilemanager

import (
	"context"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/seccompmanager"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRemovalTestManager(t *testing.T, cfg config.Config, k8s objectcache.K8sObjectCache) *ContainerProfileManager {
	t.Helper()
	t.Setenv("QUEUE_DIR", t.TempDir())
	cpm, err := NewContainerProfileManager(context.Background(), cfg, &k8sclient.K8sClientMock{}, k8s,
		&storage.StorageHttpClientMock{}, &dnsmanager.DNSManagerMock{}, &seccompmanager.SeccompManagerMock{}, nil, nil, nil)
	require.NoError(t, err)
	t.Cleanup(cpm.Close)
	return cpm
}

func removalTestContainer(id string) *containercollection.Container {
	return &containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
			ContainerID:   id,
			ContainerName: "init",
			ContainerPID:  42,
		}},
		K8s: containercollection.K8sMetadata{BasicK8sMetadata: eventtypes.BasicK8sMetadata{
			Namespace: "default",
			PodName:   "pod",
		}},
	}
}

func newEntry() *ContainerEntry {
	return &ContainerEntry{data: &containerData{}, ready: make(chan struct{})}
}

// fetchHookK8sCache runs onGet before each shared-data lookup.
type fetchHookK8sCache struct {
	*objectcache.K8sObjectCacheMock
	onGet func()
}

func (k *fetchHookK8sCache) GetSharedContainerData(containerID string) *objectcache.WatchedContainerData {
	k.onGet()
	return k.K8sObjectCacheMock.GetSharedContainerData(containerID)
}

// Removal before shared data exists aborts the registration at once.
// Covers the regular and namespace-filter paths.
func TestContainerCallback_RemovalAbortsPendingRegistration(t *testing.T) {
	for name, cfg := range map[string]config.Config{
		"regular":          {MaxSniffingTime: time.Hour},
		"namespace filter": {MaxSniffingTime: time.Hour, NamespaceFilterFile: "filter.yaml"},
	} {
		t.Run(name, func(t *testing.T) {
			cpm := newRemovalTestManager(t, cfg, &objectcache.K8sObjectCacheMock{})
			container := removalTestContainer("short-lived")

			cpm.ContainerCallback(containercollection.PubSubEvent{Type: containercollection.EventTypeAddContainer, Container: container})
			require.Eventually(t, func() bool {
				_, ok := cpm.getContainerEntry("short-lived")
				return ok
			}, 2*time.Second, 5*time.Millisecond, "registration must be waiting for shared data")

			cpm.ContainerCallback(containercollection.PubSubEvent{Type: containercollection.EventTypeRemoveContainer, Container: container})
			require.Eventually(t, func() bool {
				_, ok := cpm.getContainerEntry("short-lived")
				return !ok && cpm.pendingAdds.Len("short-lived") == 0
			}, 2*time.Second, 5*time.Millisecond, "removal must abort the registration and clean up")
		})
	}
}

// Removal after shared data arrived must not close ready early.
// A deletion would then hit a nil SyncChannel.
func TestAddContainerWithTimeout_RemovalAfterSharedDataWaitsForRegistration(t *testing.T) {
	mock := &objectcache.K8sObjectCacheMock{}
	mock.SetSharedContainerData("racing", &objectcache.WatchedContainerData{ContainerID: "racing"})
	var cpm *ContainerProfileManager
	k8s := &fetchHookK8sCache{K8sObjectCacheMock: mock, onGet: func() { cpm.pendingAdds.Cancel("racing") }}
	cpm = newRemovalTestManager(t, config.Config{MaxSniffingTime: time.Hour, InitialDelay: time.Minute, UpdateDataPeriod: time.Minute}, k8s)

	parent, release := cpm.pendingAdds.Track("racing")
	defer release()
	cpm.addContainerWithTimeout(parent, removalTestContainer("racing"))

	entry, ok := cpm.getContainerEntry("racing")
	require.True(t, ok, "registration past the shared-data wait must complete")
	select {
	case <-entry.ready:
	default:
		t.Fatal("ready must be closed once registration completes")
	}
	entry.mu.RLock()
	defer entry.mu.RUnlock()
	require.NotNil(t, entry.data.watchedContainerData)
	assert.NotNil(t, entry.data.watchedContainerData.SyncChannel, "ready must not be released before SyncChannel exists")
}

// A replayed add woken by ready must find the failed entry gone.
func TestAbandonEntry_UntracksBeforeReleasingWaiters(t *testing.T) {
	cpm := &ContainerProfileManager{containers: make(map[string]*ContainerEntry)}
	entry := newEntry()
	require.True(t, cpm.addContainerEntryIfAbsent("c", entry))

	stillTracked := make(chan bool, 1)
	go func() {
		<-entry.ready
		_, ok := cpm.getContainerEntry("c")
		stillTracked <- ok
	}()
	cpm.abandonEntry("c", entry)
	assert.False(t, <-stillTracked)
}

// Only a removal downgrades the failure.
// Live container at the deadline, or shared data present: still an error.
func TestAddContainer_FailureClassification(t *testing.T) {
	k8s := &objectcache.K8sObjectCacheMock{}
	cpm := newRemovalTestManager(t, config.Config{MaxSniffingTime: time.Hour, InitialDelay: time.Minute, UpdateDataPeriod: time.Minute}, k8s)

	t.Run("removed while waiting for shared data", func(t *testing.T) {
		parent, release := cpm.pendingAdds.Track("removed")
		defer release()
		ctx, cancel := context.WithTimeout(parent, time.Minute)
		defer cancel()
		time.AfterFunc(20*time.Millisecond, func() { cpm.pendingAdds.Cancel("removed") })

		require.Error(t, cpm.addContainer(removalTestContainer("removed"), newEntry(), ctx))
		assert.True(t, utils.RemovedDuringAdd(ctx))
	})

	t.Run("live container without shared data", func(t *testing.T) {
		parent, release := cpm.pendingAdds.Track("live")
		defer release()
		ctx, cancel := context.WithTimeout(parent, 50*time.Millisecond)
		defer cancel()

		require.Error(t, cpm.addContainer(removalTestContainer("live"), newEntry(), ctx))
		assert.False(t, utils.RemovedDuringAdd(ctx))
	})

	t.Run("failure with shared data present", func(t *testing.T) {
		k8s.SetSharedContainerData("present", &objectcache.WatchedContainerData{ContainerID: "present"})
		parent, release := cpm.pendingAdds.Track("present")
		defer release()
		ctx, cancel := context.WithTimeout(parent, time.Minute)
		defer cancel()

		// Untracked entry: addContainer fails after the shared-data wait.
		require.Error(t, cpm.addContainer(removalTestContainer("present"), newEntry(), ctx))
		assert.False(t, utils.RemovedDuringAdd(ctx))
	})
}
