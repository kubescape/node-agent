package containerprofilemanager

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v5"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/otelsetup"
	"github.com/stretchr/testify/require"
)

func TestPermanentRejectionStopsMonitoringWithoutCompletion(t *testing.T) {
	for _, tc := range []struct {
		name     string
		host     bool
		finalize error
	}{
		{name: "container"},
		{name: "host", host: true},
		{name: "termination_flush", finalize: ContainerHasTerminatedError},
		{name: "max_time_flush", finalize: ContainerReachedMaxTime},
	} {
		t.Run(tc.name, func(t *testing.T) {
			container := newHostPseudoContainer()
			if !tc.host {
				container.Runtime.ContainerID = "container"
				container.Runtime.ContainerPID = 2
			}
			id := container.Runtime.ContainerID
			watched := &objectcache.WatchedContainerData{
				ContainerID: id, SyncChannel: make(chan error, 3),
				UpdateDataTicker: time.NewTicker(time.Hour), AckChan: make(chan struct{}, 1),
			}
			defer watched.UpdateDataTicker.Stop()
			watched.SetStatus(objectcache.WatchedContainerStatusReady)
			watched.SetCompletionStatus(objectcache.WatchedContainerCompletionStatusFull)
			ready := make(chan struct{})
			close(ready)
			timer := time.NewTimer(time.Hour)
			defer timer.Stop()
			entry := &ContainerEntry{ready: ready, data: &containerData{watchedContainerData: watched, timer: timer, queueErrors: make(chan error, 1), monitorDone: make(chan struct{})}}
			ended := make(chan *containercollection.Container, 1)
			completed := &completionNotifierMock{completed: make(chan string, 1)}
			cpm := &ContainerProfileManager{
				containers:       map[string]*ContainerEntry{id: entry},
				lifecycleTracker: otelsetup.NewProfileLifecycleTracker(), completionNotifier: completed,
				maxSniffTimeNotificationChan: []chan *containercollection.Container{ended},
			}
			cause := errors.New("invalid report")
			rejection := fmt.Errorf("backend response: %w", backoff.Permanent(cause))
			if tc.finalize != nil {
				// Reject during the final syscall flush, after the monitor has
				// already checked the queue and accepted the lifecycle signal.
				watched.SetStatus(objectcache.WatchedContainerStatusCompleted)
				cpm.SetSyscallFlusher(func() { cpm.OnQueueError(nil, id, rejection) })
				watched.SyncChannel <- tc.finalize
			} else {
				// Fill the control channel and deliver multiple already queued report
				// failures before monitoring starts. None may block under the entry lock.
				for range cap(watched.SyncChannel) {
					watched.SyncChannel <- ContainerReachedMaxTime
				}
				delivered := make(chan struct{})
				go func() {
					cpm.OnQueueError(nil, id, rejection)
					for range 64 {
						cpm.OnQueueError(nil, id, backoff.Permanent(errors.New("later rejection")))
					}
					close(delivered)
				}()
				select {
				case <-delivered:
				case <-time.After(time.Second):
					t.Fatal("repeated queue callbacks blocked with a full control channel")
				}
			}
			done := make(chan error, 1)
			go func() { done <- cpm.monitorContainer(container, watched, entry.data) }()
			select {
			case result := <-done:
				require.ErrorIs(t, result, rejection)
				var permanent *backoff.PermanentError
				require.ErrorAs(t, result, &permanent)
				require.Contains(t, result.Error(), cause.Error())
			case <-time.After(3 * time.Second):
				t.Fatal("permanent rejection deadlocked monitoring cleanup")
			}
			require.Equal(t, objectcache.WatchedContainerStatusRejected, watched.GetStatus())
			require.NotEqual(t, objectcache.WatchedContainerStatusCompleted, watched.GetStatus())
			require.NotEqual(t, objectcache.WatchedContainerStatusTooLarge, watched.GetStatus())
			_, exists := cpm.getContainerEntry(id)
			require.False(t, exists, "rejected container must stop accepting learned events")
			require.Nil(t, entry.data)
			require.False(t, timer.Stop(), "sniffing timer was stopped by cleanup")
			select {
			case got := <-ended:
				require.Same(t, container, got)
			default:
				t.Fatal("missing end-of-life notification")
			}
			select {
			case <-completed.completed:
				t.Fatal("rejection falsely announced completed profile")
			default:
			}
			require.Empty(t, watched.AckChan, "cleanup must not self-signal a stopped monitor")
			cpm.deleteContainer(container) // A later runtime Remove remains safe.
		})
	}
}
