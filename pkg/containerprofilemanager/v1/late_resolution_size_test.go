package containerprofilemanager

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DmitriyVTitov/size"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/common"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/hostidentity"
	"github.com/kubescape/node-agent/pkg/seccompmanager"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/require"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// TestSaveContainerProfile_LateResolutionSizeBudget checks that resolved peers split within budget while preserving ports and report order.
func TestSaveContainerProfile_LateResolutionSizeBudget(t *testing.T) {
	for _, tc := range []struct {
		name      string
		peerKind  EndpointKind
		eventKind EndpointKind
	}{
		{name: "raw pod", peerKind: EndpointKindPod, eventKind: EndpointKindRaw},
		{name: "raw service", peerKind: EndpointKindService, eventKind: EndpointKindRaw},
		{name: "resolved service", peerKind: EndpointKindService, eventKind: EndpointKindService},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("QUEUE_DIR", t.TempDir())
			sink := &storage.StorageHttpClientMock{}
			manager, err := NewContainerProfileManager(context.Background(), config.Config{}, nil, nil, sink, nil, &seccompmanager.SeccompManagerMock{}, nil, nil, nil)
			require.NoError(t, err)
			t.Cleanup(manager.Close)
			watched := hostidentity.BuildHostWatchedContainerData("node-1")
			container := hostContainerWithIdentity(newHostPseudoContainer(), watched, "kubescape")
			data := &containerData{watchedContainerData: watched, networks: mapset.NewSet[NetworkEvent]()}
			inventory := newMockK8sInventory()
			manager.k8sInventory = inventory
			labels := map[string]string{}
			serviceLabels := map[string]any{}
			for i := range 40 {
				key := fmt.Sprintf("label-%d", i)
				labels[key] = strings.Repeat("v", 63)
				serviceLabels[key] = labels[key]
			}
			if tc.peerKind == EndpointKindService {
				manager.k8sClient = &servicePortTestClient{service: newServiceWorkload("api", serviceLabels, map[string]any{"name": "web", "port": 80, "targetPort": "http", "protocol": "TCP"}), kubeClient: fake.NewClientset()}
			}
			for i := range 2 {
				ip := fmt.Sprintf("10.0.0.%d", i+1)
				namespace := fmt.Sprintf("peer-%d", i)
				event := NetworkEvent{Port: 80, Protocol: "tcp", PktType: utils.OutgoingPktType, Destination: Destination{Kind: tc.eventKind, IPAddress: ip}}
				if tc.eventKind == EndpointKindService {
					event.Destination.Name = "api"
					event.Destination.Namespace = namespace
					if data.servicePorts == nil {
						data.servicePorts = make(map[NetworkEvent][]uint16)
					}
					data.servicePorts[event] = []uint16{8080, 9090, 10000}
				}
				data.networks.Add(event)
				data.size.Add(int64(size.Of(event) + networkNeighborIncrement(data, event)))
				if tc.peerKind == EndpointKindService {
					for j, port := range []int32{8080, 9090, 10000} {
						slice := newEndpointSlice(fmt.Sprintf("slice-%d", j), "api", discoveryv1.EndpointPort{Name: new("web"), Port: new(port)})
						slice.Namespace = namespace
						_, err := manager.k8sClient.(*servicePortTestClient).kubeClient.DiscoveryV1().EndpointSlices(namespace).Create(context.Background(), slice, metav1.CreateOptions{})
						require.NoError(t, err)
					}
				}
				meta := common.SlimObjectMeta{Name: "api", Namespace: namespace, Labels: labels}
				if tc.peerKind == EndpointKindPod {
					inventory.podsByIP[ip] = &common.SlimPod{SlimObjectMeta: meta, Status: common.SlimPodStatus{PodIP: ip}}
				} else {
					inventory.svcsByIP[ip] = &common.SlimService{SlimObjectMeta: meta, Spec: common.SlimServiceSpec{ClusterIP: ip}}
				}
			}
			// Each materialized peer fits, but their combined selectors exceed the estimate.
			neighbors := data.getEgressNetworkNeighbors(watched.ContainerID, container.K8s.Namespace, manager.k8sClient, nil, inventory, nil, false)
			require.Len(t, neighbors, 2)
			manager.cfg.MaxTsProfileSize = int64(size.Of(neighbors[0])*3/2 + 1000)
			require.Less(t, data.size.Load(), manager.cfg.MaxTsProfileSize)
			require.Greater(t, int64(size.Of(neighbors)), manager.cfg.MaxTsProfileSize)
			require.NoError(t, manager.saveContainerProfile(watched, container, data, false))
			if tc.peerKind == EndpointKindService {
				for i := range 2 {
					require.NoError(t, manager.k8sClient.(*servicePortTestClient).kubeClient.DiscoveryV1().EndpointSlices(fmt.Sprintf("peer-%d", i)).Delete(context.Background(), "slice-2", metav1.DeleteOptions{}))
				}
			}
			require.Eventually(t, func() bool { return len(sink.ContainerProfilesSnapshot()) >= 2 }, 16*time.Second, 10*time.Millisecond)
			profiles := sink.ContainerProfilesSnapshot()
			require.Len(t, profiles, 2)
			previous := time.Time{}.String()
			for _, profile := range profiles {
				require.LessOrEqual(t, int64(size.Of(profile.Spec)), manager.cfg.MaxTsProfileSize)
				require.Len(t, profile.Spec.Egress, 1)
				require.NotNil(t, profile.Spec.Egress[0].PodSelector)
				require.Equal(t, labels, profile.Spec.Egress[0].PodSelector.MatchLabels)
				if tc.peerKind == EndpointKindService {
					require.Equal(t, []int32{8080, 9090, 10000}, networkPortValues(profile.Spec.Egress[0].Ports))
				}
				require.Equal(t, previous, profile.Annotations[helpersv1.PreviousReportTimestampMetadataKey])
				previous = profile.Annotations[helpersv1.ReportTimestampMetadataKey]
			}
			require.Equal(t, watched.CurrentReportTimestamp.String(), previous)
		})
	}
}
