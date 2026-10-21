package containerprofilemanager

import (
	"context"
	"testing"
	"time"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/hostidentity"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/seccompmanager"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/require"
)

// TestSyscallFinalizationWaitsForDelivery exercises the real monitor and queue:
// acknowledged batches survive finalization, while failed flushes produce partial
// profiles. The delayed batch outlasts the former 500ms settling window.
func TestSyscallFinalizationWaitsForDelivery(t *testing.T) {
	for _, terminal := range []struct {
		name string
		err  error
	}{
		{"termination", ContainerHasTerminatedError},
		{"max-time", ContainerReachedMaxTime},
	} {
		for _, mode := range []string{"early", "delayed", "failed", "canceled"} {
			name := terminal.name + "/" + mode
			t.Run(name, func(t *testing.T) {
				t.Setenv("QUEUE_DIR", t.TempDir())
				sink := &storage.StorageHttpClientMock{}
				cpm, err := NewContainerProfileManager(context.Background(), config.Config{MaxTsProfileSize: 10 << 20}, nil, nil,
					sink, nil, &seccompmanager.SeccompManagerMock{}, nil, nil, nil)
				require.NoError(t, err)
				t.Cleanup(cpm.Close)

				// Reuse valid profile identity, but exercise ordinary-container
				// finalization rather than the host's indefinite monitoring path.
				watched := hostidentity.BuildHostWatchedContainerData("node-1")
				container := hostContainerWithIdentity(newHostPseudoContainer(), watched, "kubescape")
				watched.ContainerID = "syscall-finalization-repro"
				container.Runtime.ContainerID = watched.ContainerID
				container.Runtime.ContainerPID = 2
				require.False(t, utils.IsHostContainer(container))
				watched.UpdateDataTicker = time.NewTicker(time.Hour)
				t.Cleanup(watched.UpdateDataTicker.Stop)
				watched.SyncChannel = make(chan error, 1)
				watched.AckChan = make(chan struct{}, 1)
				watched.SetCompletionStatus(objectcache.WatchedContainerCompletionStatusFull)
				watched.SetStatus(objectcache.WatchedContainerStatusReady)
				if terminal.err == ContainerHasTerminatedError {
					// The deletion lifecycle sets this before signaling the monitor.
					watched.SetStatus(objectcache.WatchedContainerStatusCompleted)
				}
				ready := make(chan struct{})
				close(ready)
				entry := &ContainerEntry{ready: ready, data: &containerData{
					watchedContainerData: watched, queueErrors: make(chan error, 1), monitorDone: make(chan struct{}),
				}}
				require.True(t, cpm.addContainerEntryIfAbsent(watched.ContainerID, entry))
				cpm.ReportSyscalls(watched.ContainerID, []string{"read"})

				ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
				defer cancel()
				cpm.ctx = ctx
				flushRequested := make(chan struct{})
				releaseBatch := make(chan struct{})
				batchDelivered := make(chan struct{})
				const marker = "fchmodat"
				go func() {
					defer close(batchDelivered)
					select {
					case <-flushRequested:
					case <-ctx.Done():
						return
					}
					select {
					case <-releaseBatch:
						cpm.ReportSyscalls(watched.ContainerID, []string{marker})
					case <-ctx.Done():
					}
				}()
				cpm.SetSyscallFlusherWithContext(func(flushCtx context.Context) error {
					close(flushRequested)
					switch mode {
					case "failed":
						return context.DeadlineExceeded
					case "canceled":
						<-flushCtx.Done()
						return flushCtx.Err()
					case "early":
						close(releaseBatch)
					}
					select {
					case <-batchDelivered:
						return flushCtx.Err()
					case <-flushCtx.Done():
						return flushCtx.Err()
					}
				})
				monitorResult := make(chan error, 1)
				watched.SyncChannel <- terminal.err
				go func() { monitorResult <- cpm.monitorContainer(container, watched, entry.data) }()
				t.Cleanup(func() {
					cancel()
					<-batchDelivered
					select {
					case <-entry.data.monitorDone:
					case <-time.After(2 * time.Second):
						t.Error("monitor did not stop")
					}
				})

				select {
				case <-flushRequested:
				case <-ctx.Done():
					t.Fatal("finalization did not request a syscall flush")
				}
				if mode == "delayed" {
					// Hold delivery beyond the old fixed delay. The gate, rather
					// than scheduler timing, controls when acknowledgment occurs.
					select {
					case err := <-monitorResult:
						t.Fatalf("finalized before delivery: %v", err)
					case <-time.After(600 * time.Millisecond):
					}
					require.Empty(t, sink.ContainerProfilesSnapshot())
					close(releaseBatch)
				} else if mode == "canceled" {
					cancel()
				}
				select {
				case err := <-monitorResult:
					require.ErrorIs(t, err, terminal.err)
				case <-time.After(7 * time.Second):
					t.Fatal("finalization did not finish")
				}
				require.Eventually(t, func() bool { return len(sink.ContainerProfilesSnapshot()) == 1 }, 8*time.Second, 10*time.Millisecond)
				profiles := sink.ContainerProfilesSnapshot()
				require.Len(t, profiles, 1)
				profile := profiles[0]
				require.Equal(t, string(objectcache.WatchedContainerStatusCompleted), profile.Annotations[helpersv1.StatusMetadataKey])
				wantCompletion := objectcache.WatchedContainerCompletionStatusFull
				want := []string{"read", marker}
				if mode == "failed" || mode == "canceled" {
					want = []string{"read"}
					wantCompletion = objectcache.WatchedContainerCompletionStatusPartial
				}
				require.Equal(t, string(wantCompletion), profile.Annotations[helpersv1.CompletionMetadataKey])
				require.ElementsMatch(t, want, profile.Spec.Syscalls)
				t.Logf("captured terminal profile: status=%s completion=%s syscalls=%v; mode=%s marker=%s",
					profile.Annotations[helpersv1.StatusMetadataKey], profile.Annotations[helpersv1.CompletionMetadataKey], profile.Spec.Syscalls, mode, marker)
			})
		}
	}
}
