package containerprofilemanager

import (
	"context"
	"testing"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/common"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/hostidentity"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/seccompmanager"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSaveContainerProfile_DeferredOnlyPreservesReportTimestamps checks that a skipped flush leaves no timestamp link to an unqueued report.
func TestSaveContainerProfile_DeferredOnlyPreservesReportTimestamps(t *testing.T) {
	for _, priorReport := range []bool{false, true} {
		name := "first report"
		if priorReport {
			name = "after prior report"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv("QUEUE_DIR", t.TempDir())
			storageClient := &storage.StorageHttpClientMock{}
			cpm, err := NewContainerProfileManager(context.Background(), config.Config{}, nil, nil,
				storageClient, nil, &seccompmanager.SeccompManagerMock{}, nil, nil, nil)
			require.NoError(t, err)
			t.Cleanup(cpm.Close)

			watched := hostidentity.BuildHostWatchedContainerData("node-1")
			container := hostContainerWithIdentity(newHostPseudoContainer(), watched, "kubescape")
			data := &containerData{watchedContainerData: watched}
			wantReports := 1
			if priorReport {
				data.syscalls = mapset.NewSet("openat")
				require.NoError(t, cpm.saveContainerProfile(watched, container, data, false))
				wantReports++
			}
			previous, current := watched.PreviousReportTimestamp, watched.CurrentReportTimestamp
			// Isolate a deferred-only flush with no unreported lifecycle change.
			data.lastReportedCompletion = string(watched.GetCompletionStatus())
			data.lastReportedStatus = string(watched.GetStatus())
			data.networks = mapset.NewSet(NetworkEvent{
				Port: 443, Protocol: "tcp", PktType: utils.OutgoingPktType,
				Destination: Destination{Kind: EndpointKindRaw, IPAddress: "10.50.1.20"},
			})

			// An unresolved private peer skips this flush but must not create a link
			// to a report that was never queued.
			require.NoError(t, cpm.saveContainerProfile(watched, container, data, false))
			assert.Equal(t, previous, watched.PreviousReportTimestamp)
			assert.Equal(t, current, watched.CurrentReportTimestamp)
			require.NotNil(t, data.networks)
			require.Equal(t, 1, data.networks.Cardinality())

			// The next flush emits the retained peer with the last emitted timestamp.
			require.NoError(t, cpm.saveContainerProfile(watched, container, data, false))
			assert.Equal(t, current, watched.PreviousReportTimestamp)
			require.Eventually(t, func() bool {
				return len(storageClient.ContainerProfilesSnapshot()) == wantReports
			}, 8*time.Second, 10*time.Millisecond)
			profiles := storageClient.ContainerProfilesSnapshot()
			last := profiles[len(profiles)-1]
			assert.Equal(t, current.String(), last.Annotations[helpersv1.PreviousReportTimestampMetadataKey])
			assert.Equal(t, watched.CurrentReportTimestamp.String(), last.Annotations[helpersv1.ReportTimestampMetadataKey])
			require.Len(t, last.Spec.Egress, 1)
			assert.Equal(t, "10.50.1.20", last.Spec.Egress[0].IPAddress)
			if priorReport {
				assert.Equal(t, profiles[0].Annotations[helpersv1.ReportTimestampMetadataKey], last.Annotations[helpersv1.PreviousReportTimestampMetadataKey])
			}
		})
	}
}

// TestSaveContainerProfile_RapidFlushesRetainUnresolvedPeer verifies back-to-back
// size flushes keep a peer retryable until the informer can supply its identity.
func TestSaveContainerProfile_RapidFlushesRetainUnresolvedPeer(t *testing.T) {
	t.Setenv("QUEUE_DIR", t.TempDir())
	sink := &storage.StorageHttpClientMock{}
	cpm, err := NewContainerProfileManager(context.Background(), config.Config{UpdateDataPeriod: time.Minute}, nil, nil,
		sink, nil, &seccompmanager.SeccompManagerMock{}, nil, nil, nil)
	require.NoError(t, err)
	t.Cleanup(cpm.Close)
	inventory := newMockK8sInventory()
	cpm.k8sInventory = inventory
	watched := hostidentity.BuildHostWatchedContainerData("node-1")
	container := hostContainerWithIdentity(newHostPseudoContainer(), watched, "kubescape")
	data := &containerData{
		watchedContainerData:   watched,
		lastReportedCompletion: string(watched.GetCompletionStatus()),
		lastReportedStatus:     string(watched.GetStatus()),
		networks: mapset.NewSet(NetworkEvent{Port: 443, Protocol: "tcp", PktType: utils.OutgoingPktType,
			Destination: Destination{Kind: EndpointKindRaw, IPAddress: "10.50.1.20"}}),
	}
	previous := watched.CurrentReportTimestamp
	for range 2 {
		require.NoError(t, cpm.saveContainerProfile(watched, container, data, false))
		require.Equal(t, previous, watched.CurrentReportTimestamp)
		require.Equal(t, 1, data.networks.Cardinality())
		require.Empty(t, sink.ContainerProfilesSnapshot())
	}
	inventory.podsByIP["10.50.1.20"] = &common.SlimPod{
		SlimObjectMeta: common.SlimObjectMeta{Name: "late", Namespace: "peer", Labels: map[string]string{"app": "late"}},
		Status:         common.SlimPodStatus{PodIP: "10.50.1.20"},
	}
	require.NoError(t, cpm.saveContainerProfile(watched, container, data, false))
	require.Eventually(t, func() bool { return len(sink.ContainerProfilesSnapshot()) == 1 }, 8*time.Second, 10*time.Millisecond)
	profile := sink.ContainerProfilesSnapshot()[0]
	require.Len(t, profile.Spec.Egress, 1)
	require.Empty(t, profile.Spec.Egress[0].IPAddress)
	require.Equal(t, map[string]string{"app": "late"}, profile.Spec.Egress[0].PodSelector.MatchLabels)
	require.Equal(t, previous.String(), profile.Annotations[helpersv1.PreviousReportTimestampMetadataKey])
	require.Empty(t, data.networkDeferredUntil)
}

// TestSaveContainerProfile_DeferredOnlyReportsStatusChanges verifies deferred peers
// cannot hide a completion or status transition, and the later peer follows that report.
func TestSaveContainerProfile_DeferredOnlyReportsStatusChanges(t *testing.T) {
	for _, transition := range []string{"dropped events", "status"} {
		t.Run(transition, func(t *testing.T) {
			t.Setenv("QUEUE_DIR", t.TempDir())
			sink := &storage.StorageHttpClientMock{}
			cpm, err := NewContainerProfileManager(context.Background(), config.Config{}, nil, nil,
				sink, nil, &seccompmanager.SeccompManagerMock{}, nil, nil, nil)
			require.NoError(t, err)
			t.Cleanup(cpm.Close)
			watched := hostidentity.BuildHostWatchedContainerData("node-1")
			container := hostContainerWithIdentity(newHostPseudoContainer(), watched, "kubescape")
			data := &containerData{
				watchedContainerData:   watched,
				lastReportedCompletion: string(watched.GetCompletionStatus()),
				lastReportedStatus:     string(watched.GetStatus()),
				networks: mapset.NewSet(NetworkEvent{Port: 443, Protocol: "tcp", PktType: utils.OutgoingPktType,
					Destination: Destination{Kind: EndpointKindRaw, IPAddress: "10.50.1.20"}}),
			}
			if transition == "dropped events" {
				data.droppedEvents = true
			} else {
				watched.SetStatus(objectcache.WatchedContainerStatusCompleted)
			}
			previous := watched.CurrentReportTimestamp
			require.NoError(t, cpm.saveContainerProfile(watched, container, data, false))
			require.Eventually(t, func() bool { return len(sink.ContainerProfilesSnapshot()) == 1 }, 8*time.Second, 10*time.Millisecond)
			first := sink.ContainerProfilesSnapshot()[0]
			require.Empty(t, first.Spec.Egress)
			require.Equal(t, string(watched.GetCompletionStatus()), first.Annotations[helpersv1.CompletionMetadataKey])
			require.Equal(t, string(watched.GetStatus()), first.Annotations[helpersv1.StatusMetadataKey])
			require.Equal(t, previous.String(), first.Annotations[helpersv1.PreviousReportTimestampMetadataKey])
			require.Equal(t, 1, data.networks.Cardinality())
			require.NoError(t, cpm.saveContainerProfile(watched, container, data, true))
			require.Eventually(t, func() bool { return len(sink.ContainerProfilesSnapshot()) == 2 }, 8*time.Second, 10*time.Millisecond)
			last := sink.ContainerProfilesSnapshot()[1]
			require.Len(t, last.Spec.Egress, 1)
			require.Equal(t, first.Annotations[helpersv1.ReportTimestampMetadataKey], last.Annotations[helpersv1.PreviousReportTimestampMetadataKey])
		})
	}
}
