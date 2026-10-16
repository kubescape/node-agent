package containerprofilemanager

import (
	"maps"
	"testing"
	"time"

	"github.com/DmitriyVTitov/size"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/common"
	"github.com/stretchr/testify/require"
)

// TestNetworkDeferralBudgetEmitsOverflow verifies repeated fresh batches cannot
// grow deferred memory beyond its budget and overflow observations still reach output.
func TestNetworkDeferralBudgetEmitsOverflow(t *testing.T) {
	for _, kind := range []EndpointKind{EndpointKindRaw, EndpointKindService} {
		for _, final := range []string{"expired", "forced"} {
			t.Run(string(kind)+"/"+final, func(t *testing.T) {
				cd := &containerData{networkDeferralDuration: time.Hour, networkFlushForSize: true, networks: mapset.NewSet[NetworkEvent]()}
				client := &servicePortTestClient{service: newServiceWorkload("api", nil)}
				event := serviceNetworkEvent(80, "tcp")
				event.Destination.Kind = kind
				event.Destination.IPAddress = "10.96.0.42"
				if kind == EndpointKindService {
					cd.servicePorts = map[NetworkEvent][]uint16{event: {8080, 9090}}
				}
				cd.networkDeferredSizeLimit = 2*int64(size.Of(event)+networkNeighborIncrement(cd, event)) + 1
				var emitted []int32
				var deadlines map[NetworkEvent]time.Time
				for i := range 10 {
					current := event
					current.Port = uint16(80 + i)
					cd.networks.Add(current)
					cd.activeNetworks = mapset.NewSet(current)
					if kind == EndpointKindService {
						cd.servicePorts[current] = []uint16{8080, 9090}
					}
					for _, neighbor := range cd.getEgressNetworkNeighbors("", "default", client, nil, nil, nil, false) {
						require.Equal(t, current.Destination.IPAddress, neighbor.IPAddress)
						emitted = append(emitted, networkPortValues(neighbor.Ports)...)
					}
					cd.emptyEvents()
					require.LessOrEqual(t, cd.networks.Cardinality(), 2, "each pressure flush must leave the backlog bounded")
					require.LessOrEqual(t, cd.networkDeferredSize, cd.networkDeferredSizeLimit)
					require.Zero(t, cd.size.Load())
					if i == 1 {
						deadlines = maps.Clone(cd.networkDeferredUntil)
					}
					if i > 1 {
						require.Equal(t, deadlines, cd.networkDeferredUntil, "overflow must not change admitted deadlines")
					}
				}
				require.Equal(t, 2, cd.networks.Cardinality())
				require.ElementsMatch(t, []int32{82, 83, 84, 85, 86, 87, 88, 89}, emitted)
				require.Len(t, cd.networkDeferredSizes, 2)
				if kind == EndpointKindService {
					require.Len(t, cd.servicePorts, 2)
				}
				cd.networkFlushForSize = false
				if final == "expired" {
					for event := range cd.networkDeferredUntil {
						cd.networkDeferredUntil[event] = time.Now().Add(-time.Second)
					}
				}
				for _, neighbor := range cd.getEgressNetworkNeighbors("", "default", client, nil, nil, nil, final == "forced") {
					emitted = append(emitted, networkPortValues(neighbor.Ports)...)
				}
				cd.emptyEvents()
				require.ElementsMatch(t, []int32{80, 81, 82, 83, 84, 85, 86, 87, 88, 89}, emitted)
				require.Nil(t, cd.networks)
				require.Nil(t, cd.networkDeferredSizes)
				require.Nil(t, cd.networkDeferredUntil)
				require.Nil(t, cd.servicePorts)
				require.Zero(t, cd.networkDeferredSize)
			})
		}
	}
}

// TestNetworkDeferralBudgetReclaimsResolvedEntries verifies periodic delivery frees
// exactly the consumed peer's budget while another pending peer keeps its deadline.
func TestNetworkDeferralBudgetReclaimsResolvedEntries(t *testing.T) {
	first := serviceNetworkEvent(80, "tcp")
	first.Destination.Kind = EndpointKindRaw
	first.Destination.IPAddress = "10.96.0.41"
	second := first
	second.Destination.IPAddress = "10.96.0.42"
	cd := &containerData{networkDeferralDuration: time.Hour, networks: mapset.NewSet(first, second)}
	cost := int64(size.Of(first) + networkNeighborIncrement(cd, first))
	cd.networkDeferredSizeLimit = 2 * cost
	inv := newMockK8sInventory()
	require.Empty(t, cd.getEgressNetworkNeighbors("", "default", nil, nil, inv, nil, false))
	cd.emptyEvents()
	require.Equal(t, 2*cost, cd.networkDeferredSize)
	deadline := cd.networkDeferredUntil[second]
	inv.podsByIP[first.Destination.IPAddress] = &common.SlimPod{SlimObjectMeta: common.SlimObjectMeta{Name: "api", Namespace: "default", Labels: map[string]string{"app": "api"}}, Status: common.SlimPodStatus{PodIP: first.Destination.IPAddress}}
	require.Len(t, cd.getEgressNetworkNeighbors("", "default", nil, nil, inv, nil, false), 1)
	cd.emptyEvents()
	require.Equal(t, cost, cd.networkDeferredSize)
	require.Equal(t, map[NetworkEvent]int64{second: cost}, cd.networkDeferredSizes)
	require.Equal(t, deadline, cd.networkDeferredUntil[second])
	third := first
	third.Destination.IPAddress = "10.96.0.43"
	cd.networks.Add(third)
	cd.activeNetworks = mapset.NewSet(third)
	cd.networkFlushForSize = true
	require.Empty(t, cd.getEgressNetworkNeighbors("", "default", nil, nil, inv, nil, false), "released capacity must admit the new peer")
	cd.emptyEvents()
	require.Equal(t, 2*cost, cd.networkDeferredSize)
	require.Equal(t, 2, cd.networks.Cardinality())
	require.Equal(t, deadline, cd.networkDeferredUntil[second])
}
