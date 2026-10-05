package containerprofilemanager

import (
	"context"
	"testing"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/hostidentity"
	"github.com/kubescape/node-agent/pkg/seccompmanager"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
