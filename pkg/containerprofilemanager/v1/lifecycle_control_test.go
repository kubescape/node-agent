package containerprofilemanager

import (
	"testing"
	"testing/synctest"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/stretchr/testify/require"
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
