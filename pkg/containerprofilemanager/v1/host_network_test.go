package containerprofilemanager

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReportNetworkEventHostNetwork(t *testing.T) {
	for _, tc := range []struct {
		name        string
		containerID string
		hostNetwork bool
		pktType     string
		podHostIP   string
		wantStored  bool
	}{
		{name: "host egress", containerID: armotypes.HostContainerID, hostNetwork: true, pktType: utils.OutgoingPktType, wantStored: true},
		{name: "host ingress", containerID: armotypes.HostContainerID, hostNetwork: true, pktType: utils.HostPktType, wantStored: true},
		{name: "hostNetwork pod egress", containerID: "hostnet-pod", hostNetwork: true, pktType: utils.OutgoingPktType},
		{name: "hostNetwork pod ingress", containerID: "hostnet-pod", hostNetwork: true, pktType: utils.HostPktType},
		{name: "ordinary pod", containerID: "pod", pktType: utils.OutgoingPktType, wantStored: true},
		{name: "host unknown packet type", containerID: armotypes.HostContainerID, hostNetwork: true, pktType: "UNKNOWN"},
		{name: "host localhost ingress", containerID: armotypes.HostContainerID, hostNetwork: true, pktType: utils.HostPktType, podHostIP: "10.0.0.5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cpm, entry := newTestManager(t, tc.containerID)
			event := &utils.StructEvent{
				DstEndpoint: types.L3Endpoint{Addr: "10.0.0.5"},
				DstPort:     8080,
				Proto:       "tcp",
				PktType:     tc.pktType,
				PodHostIP:   tc.podHostIP,
				HostNetwork: tc.hostNetwork,
			}

			cpm.ReportNetworkEvent(tc.containerID, event)

			if !tc.wantStored {
				assert.Nil(t, entry.data.networks)
				assert.Zero(t, entry.data.size.Load())
				return
			}
			require.NotNil(t, entry.data.networks)
			require.Equal(t, 1, entry.data.networks.Cardinality())
			assert.True(t, entry.data.networks.Contains(NetworkEvent{
				Port:        8080,
				Protocol:    "tcp",
				PktType:     tc.pktType,
				Destination: Destination{IPAddress: "10.0.0.5"},
			}))
			assert.Positive(t, entry.data.size.Load())

			// Accepted host observations must reach the same flush set as pod observations.
			assert.Equal(t, entry.data.networks, entry.data.networkEventsForFlush(false))
		})
	}
}
