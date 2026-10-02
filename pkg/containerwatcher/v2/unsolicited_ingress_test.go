package containerwatcher

import (
	"errors"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/require"
)

func gateUnderTest(ports map[uint32]map[uint16]struct{}) *EventHandlerFactory {
	return &EventHandlerFactory{listeners: &listenerCache{byPid: map[uint32]listenerSnapshot{}, now: time.Now, read: func(pid uint32) (map[uint16]struct{}, error) {
		p, ok := ports[pid]
		if !ok {
			return nil, errors.New("no such process")
		}
		return p, nil
	}}}
}

func syn(pktType, proto string, pid uint32, port uint16) *events.EnrichedEvent {
	return &events.EnrichedEvent{Event: &utils.StructEvent{EventType: utils.NetworkEventType, PktType: pktType, Proto: proto, Pid: pid, DstPort: port}}
}

func withPid(pid uint32) *containercollection.Container {
	return &containercollection.Container{Runtime: containercollection.RuntimeMetadata{BasicRuntimeMetadata: igtypes.BasicRuntimeMetadata{ContainerPID: pid}}}
}

func TestUnsolicitedIngress_TruthTable(t *testing.T) {
	ehf := gateUnderTest(map[uint32]map[uint16]struct{}{4242: {8443: {}, 2019: {}}})
	rows := []struct {
		name string
		ev   *events.EnrichedEvent
		pid  uint32
		drop bool
	}{
		{"SYN to a listening port with no socket owner is kept", syn(utils.HostPktType, "TCP", 0, 8443), 4242, false},
		{"SYN to a closed port with no socket owner is dropped and never learned", syn(utils.HostPktType, "TCP", 0, 9999), 4242, true},
		{"a SYN the enricher attributed to a process is kept whatever the port", syn(utils.HostPktType, "TCP", 77, 9999), 4242, false},
		{"outgoing traffic is never gated", syn(utils.OutgoingPktType, "TCP", 0, 9999), 4242, false},
		{"UDP is never gated", syn(utils.HostPktType, "UDP", 0, 9999), 4242, false},
		{"a container whose procfs cannot be read yields no verdict", syn(utils.HostPktType, "TCP", 0, 9999), 404, false},
		{"a container without a pid yields no verdict", syn(utils.HostPktType, "TCP", 0, 9999), 0, false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			require.Equal(t, r.drop, ehf.unsolicitedIngress(r.ev, withPid(r.pid)))
		})
	}
}

func TestUnsolicitedIngress_NonNetworkEventsAndNilGate(t *testing.T) {
	ehf := gateUnderTest(nil)
	exec := &events.EnrichedEvent{Event: &utils.StructEvent{EventType: utils.ExecveEventType}}
	require.False(t, ehf.unsolicitedIngress(exec, withPid(1)))
	require.False(t, (&EventHandlerFactory{}).unsolicitedIngress(syn(utils.HostPktType, "TCP", 0, 9999), withPid(1)), "a factory without the cache gates nothing")
}
