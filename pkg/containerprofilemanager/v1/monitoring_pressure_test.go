package containerprofilemanager

import (
	"context"
	"fmt"
	"maps"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/common"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/hostidentity"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/seccompmanager"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes/fake"
)

// pressureInventory counts resolution attempts to expose repeated backlog processing.
type pressureInventory struct {
	*mockK8sInventory
	lookups int
}

// GetPodByIp counts each lookup while retaining the mutable informer fixture.
func (i *pressureInventory) GetPodByIp(ip string) *common.SlimPod {
	i.lookups++
	return i.mockK8sInventory.GetPodByIp(ip)
}

// TestPressureFlushDoesNotReprocessDeferredBacklog verifies pressure work follows
// fresh batches while periodic, status-only, and forced saves retain delivery guarantees.
func TestPressureFlushDoesNotReprocessDeferredBacklog(t *testing.T) {
	t.Setenv("QUEUE_DIR", t.TempDir())
	sink := &storage.StorageHttpClientMock{}
	cpm, err := NewContainerProfileManager(context.Background(), config.Config{UpdateDataPeriod: time.Hour, MaxTsProfileSize: 10 * 1024 * 1024}, nil, nil,
		sink, nil, &seccompmanager.SeccompManagerMock{}, nil, nil, nil)
	require.NoError(t, err)
	t.Cleanup(cpm.Close)
	inventory := &pressureInventory{mockK8sInventory: newMockK8sInventory()}
	cpm.k8sInventory = inventory
	client := &servicePortTestClient{service: newServiceWorkload("api", nil,
		map[string]any{"port": 443, "targetPort": 8080, "protocol": "TCP"}), kubeClient: fake.NewClientset()}
	cpm.k8sClient = client
	inventory.svcsByIP["10.60.3.1"] = &common.SlimService{SlimObjectMeta: common.SlimObjectMeta{Name: "api", Namespace: "peer"}}
	watched := hostidentity.BuildHostWatchedContainerData("node-1")
	watched.SyncChannel = make(chan error, 8)
	container := hostContainerWithIdentity(newHostPseudoContainer(), watched, "kubescape")
	data := &containerData{watchedContainerData: watched,
		lastReportedCompletion: string(watched.GetCompletionStatus()), lastReportedStatus: string(watched.GetStatus())}
	require.True(t, cpm.addContainerEntryIfAbsent(watched.ContainerID, &ContainerEntry{data: data}))
	report := func(ip string) {
		cpm.ReportNetworkEvent(watched.ContainerID, &utils.StructEvent{
			DstEndpoint: types.L3Endpoint{Addr: ip}, DstPort: 443, Proto: "tcp", PktType: utils.OutgoingPktType})
	}
	for i := range 64 {
		report(fmt.Sprintf("10.60.1.%d", i+1))
	}
	report("10.60.3.1")
	// Keep the backlog below its independent admission limit; each flush must
	// still leave its bytes out of the active budget and avoid retrying it.
	cpm.cfg.MaxTsProfileSize = 2 * data.size.Load()
	pressureSave := func() error { return cpm.saveProfileForSize(watched, container) }
	require.NoError(t, pressureSave())
	assert.Zero(t, data.size.Load(), "retained bytes must not trigger the next pressure flush")
	require.Equal(t, 65, data.networks.Cardinality())
	deadlines := maps.Clone(data.networkDeferredUntil)
	snapshots := maps.Clone(data.servicePorts)
	require.Len(t, snapshots, 1)
	for i := range 3 {
		report(fmt.Sprintf("10.60.2.%d", i+1))
		assert.Empty(t, watched.SyncChannel, "one small fresh event must not retrigger an oversized deferred batch")
		inventory.lookups = 0
		require.NoError(t, pressureSave())
		assert.Equal(t, 1, inventory.lookups, "pressure saves must resolve only the fresh event")
		assert.Zero(t, data.size.Load())
		for event, deadline := range deadlines {
			require.Equal(t, deadline, data.networkDeferredUntil[event])
		}
		for event, ports := range snapshots {
			require.Equal(t, ports, data.servicePorts[event])
		}
	}
	// A stale pressure signal must not retry pending peers or emit an unchanged row.
	inventory.lookups = 0
	require.NoError(t, pressureSave())
	assert.Zero(t, inventory.lookups)
	require.Empty(t, sink.ContainerProfilesSnapshot())
	for _, event := range data.networks.ToSlice() {
		if event.Destination.Kind == EndpointKindService {
			continue
		}
		ip := event.Destination.IPAddress
		inventory.podsByIP[ip] = &common.SlimPod{
			SlimObjectMeta: common.SlimObjectMeta{Name: "ready", Namespace: "peer", Labels: map[string]string{"app": "ready"}},
			Status:         common.SlimPodStatus{PodIP: ip},
		}
	}
	client.service = newServiceWorkload("api", map[string]any{"app": "ready"},
		map[string]any{"port": 443, "targetPort": 8080, "protocol": "TCP"})
	inventory.lookups = 0
	require.NoError(t, cpm.saveProfile(watched, container, false))
	require.Equal(t, 67, inventory.lookups, "periodic saves must retry the complete pending batch")
	require.Nil(t, data.networks)
	require.Empty(t, data.networkDeferredUntil)
	require.Empty(t, data.servicePorts)
	require.Eventually(t, func() bool { return len(sink.ContainerProfilesSnapshot()) == 1 }, 8*time.Second, 10*time.Millisecond)
	first := sink.ContainerProfilesSnapshot()[0]
	require.Len(t, first.Spec.Egress, 1)
	require.ElementsMatch(t, []int32{443, 8080}, networkPortValues(first.Spec.Egress[0].Ports))
	// Pending-only status transitions must still emit, and a final save releases the peer.
	report("10.60.4.1")
	require.NoError(t, pressureSave())
	watched.SetCompletionStatus(objectcache.WatchedContainerCompletionStatusPartial)
	inventory.lookups = 0
	require.NoError(t, pressureSave())
	assert.Zero(t, inventory.lookups)
	require.Eventually(t, func() bool { return len(sink.ContainerProfilesSnapshot()) == 2 }, 8*time.Second, 10*time.Millisecond)
	metadata := sink.ContainerProfilesSnapshot()[1]
	require.Empty(t, metadata.Spec.Egress)
	require.Equal(t, string(objectcache.WatchedContainerCompletionStatusPartial), metadata.Annotations[helpersv1.CompletionMetadataKey])
	require.NoError(t, cpm.saveProfile(watched, container, true))
	require.Eventually(t, func() bool { return len(sink.ContainerProfilesSnapshot()) == 3 }, 8*time.Second, 10*time.Millisecond)
	last := sink.ContainerProfilesSnapshot()[2]
	require.Len(t, last.Spec.Egress, 1)
	require.Equal(t, "10.60.4.1", last.Spec.Egress[0].IPAddress)
	require.Equal(t, first.Annotations[helpersv1.ReportTimestampMetadataKey], metadata.Annotations[helpersv1.PreviousReportTimestampMetadataKey])
	require.Equal(t, metadata.Annotations[helpersv1.ReportTimestampMetadataKey], last.Annotations[helpersv1.PreviousReportTimestampMetadataKey])
	assert.Nil(t, data.networks)
}
