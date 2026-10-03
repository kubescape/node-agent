package containerprofilemanager

import (
	"testing"
	"testing/synctest"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	containerinstance "github.com/kubescape/k8s-interface/instanceidhandler/v1/containerinstance"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerprofilemanager/v1/queue"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/otelsetup"
	"github.com/kubescape/node-agent/pkg/seccompmanager"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestLifecycleSignalRejectionUnblocksFullControlChannel(t *testing.T) {
	for _, operation := range []string{"max time", "removal"} {
		t.Run(operation, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				container := newHostPseudoContainer()
				watched := &objectcache.WatchedContainerData{
					SyncChannel: make(chan error, 1), AckChan: make(chan struct{}, 1),
				}
				watched.SetStatus(objectcache.WatchedContainerStatusReady)
				watched.SyncChannel <- ProfileRequiresSplit
				data := &containerData{watchedContainerData: watched, monitorDone: make(chan struct{})}
				entry := &ContainerEntry{data: data, ready: make(chan struct{})}
				close(entry.ready)
				notifications := make(chan *containercollection.Container, 1)
				cpm := &ContainerProfileManager{
					containers:                   map[string]*ContainerEntry{"host": entry},
					maxSniffTimeNotificationChan: []chan *containercollection.Container{notifications},
				}
				finished := make(chan struct{})
				go func() {
					if operation == "max time" {
						cpm.handleContainerMaxTime(container)
					} else {
						cpm.deleteContainerWithReason(container, false)
					}
					close(finished)
				}()
				synctest.Wait()
				select {
				case <-finished:
					t.Fatal("expected signal producer to wait for full control channel")
				default:
				}
				// The monitor must be able to acquire this lock to reject and
				// unblock a sender waiting for room in the control channel.
				entry.mu.Lock()
				watched.SetStatus(objectcache.WatchedContainerStatusRejected)
				close(data.monitorDone)
				entry.mu.Unlock()
				synctest.Wait()
				select {
				case <-finished:
				default:
					t.Fatal("closed monitor must unblock lifecycle signal producer")
				}
				require.Equal(t, objectcache.WatchedContainerStatusRejected, watched.GetStatus())
				require.Empty(t, notifications, "aborted max-time send must not report completion")
			})
		})
	}
}

func TestProfileSplitCoalescesFullControlChannel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		watched := &objectcache.WatchedContainerData{SyncChannel: make(chan error, 1)}
		watched.SyncChannel <- ContainerReachedMaxTime
		data := &containerData{watchedContainerData: watched}
		cpm := &ContainerProfileManager{
			cfg:        config.Config{MaxTsProfileSize: 1},
			containers: map[string]*ContainerEntry{"id": {data: data}},
		}
		finished := make(chan error, 1)
		go func() {
			finished <- cpm.withContainer("id", func(*containerData) (int, error) { return 2, nil })
		}()
		synctest.Wait()
		select {
		case err := <-finished:
			require.NoError(t, err)
		default:
			t.Fatal("split producer must not block behind existing control signal")
		}
		require.Equal(t, ContainerReachedMaxTime, <-watched.SyncChannel)
		require.Zero(t, data.size.Load())
	})
}

func TestTickerDoesNotRegressTerminalStatus(t *testing.T) {
	container := &containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{
			BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
				ContainerID:   "test-container",
				ContainerName: "test-container",
				ContainerPID:  2,
			},
		},
	}
	id := container.Runtime.ContainerID

	tickerChan := make(chan time.Time)
	watched := &objectcache.WatchedContainerData{
		ContainerID: id, SyncChannel: make(chan error, 1),
		UpdateDataTicker: &time.Ticker{C: tickerChan}, AckChan: make(chan struct{}, 1),
		InstanceID: &containerinstance.InstanceID{
			ApiVersion: "apps/v1", Namespace: "default", Kind: "Pod", Name: "pod", ContainerName: "test-container",
		},
		ContainerType: objectcache.Container,
		ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
			objectcache.Container: {{Name: "test-container"}},
		},
		ParentWorkloadSelector: &metav1.LabelSelector{},
	}
	watched.SetStatus(objectcache.WatchedContainerStatusCompleted)
	ready := make(chan struct{})
	close(ready)
	entry := &ContainerEntry{ready: ready, data: &containerData{watchedContainerData: watched, queueErrors: make(chan error, 1), monitorDone: make(chan struct{})}}
	tempDir := t.TempDir()
	t.Setenv("QUEUE_DIR", tempDir)
	qData, err := queue.NewQueueData(t.Context(), &storage.StorageHttpClientMock{}, queue.QueueConfig{
		QueueDir:     tempDir,
		MaxQueueSize: 10,
	})
	require.NoError(t, err)
	defer qData.Close()

	cpm := &ContainerProfileManager{
		containers:        map[string]*ContainerEntry{id: entry},
		lifecycleTracker:  otelsetup.NewProfileLifecycleTracker(),
		seccompManager:    &seccompmanager.SeccompManagerMock{},
		storageClient:     &storage.StorageHttpClientMock{},
		k8sClient:         &k8sclient.K8sClientMock{},
		dnsResolverClient: &dnsmanager.DNSManagerMock{},
		queueData:         qData,
	}

	monitoringDone := make(chan error, 1)
	go func() {
		monitoringDone <- cpm.monitorContainer(container, watched, entry.data)
	}()

	// Fire a tick while status is Completed
	tickerChan <- time.Now()

	// Then send termination error to stop monitorContainer
	watched.SyncChannel <- ContainerHasTerminatedError

	require.Equal(t, ContainerHasTerminatedError, <-monitoringDone)
	// Status must have remained Completed, not regressed to Ready
	require.Equal(t, objectcache.WatchedContainerStatusCompleted, watched.GetStatus())
}
