package containerwatcher

import (
	"errors"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerprofilemanager"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/eventreporters/rulepolicy"
	"github.com/kubescape/node-agent/pkg/malwaremanager"
	metricsmanager "github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/networkstream"
	"github.com/kubescape/node-agent/pkg/rulemanager"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/require"
)

func gateUnderTest(ports map[uint32]map[uint16]struct{}) *EventHandlerFactory {
	return &EventHandlerFactory{listeners: &listenerCache{byContainer: map[string]listenerSnapshot{}, now: time.Now, read: func(pid uint32) (map[uint16]struct{}, error) {
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

func withPid(id string, pid uint32) *containercollection.Container {
	return &containercollection.Container{Runtime: containercollection.RuntimeMetadata{BasicRuntimeMetadata: igtypes.BasicRuntimeMetadata{ContainerID: id, ContainerPID: pid}}}
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
			require.Equal(t, r.drop, ehf.unsolicitedIngress(r.ev, withPid("c-truth", r.pid)))
		})
	}
}

func TestUnsolicitedIngress_NonNetworkEventsAndNilGate(t *testing.T) {
	ehf := gateUnderTest(nil)
	exec := &events.EnrichedEvent{Event: &utils.StructEvent{EventType: utils.ExecveEventType}}
	require.False(t, ehf.unsolicitedIngress(exec, withPid("c-1", 1)))
	require.False(t, (&EventHandlerFactory{}).unsolicitedIngress(syn(utils.HostPktType, "TCP", 0, 9999), withPid("c-1", 1)), "a factory without the cache gates nothing")
}

type spyProfileManager struct {
	containerprofilemanager.ContainerProfileManagerMock
	dropped []string
}

func (s *spyProfileManager) ReportDroppedEvent(containerID string) {
	s.dropped = append(s.dropped, containerID)
}

type eventWithDrops struct {
	*utils.StructEvent
}

func (e *eventWithDrops) HasDroppedEvents() bool {
	return true
}

func TestProcessEvent_UnsolicitedIngressAccountsDroppedEvents(t *testing.T) {
	pmSpy := &spyProfileManager{}
	ruleMock := &rulemanager.RuleManagerMock{}
	cc := &containercollection.ContainerCollection{}

	factory := NewEventHandlerFactory(
		config.Config{},
		cc,
		pmSpy,
		&dnsmanager.DNSManagerMock{},
		ruleMock,
		&malwaremanager.MalwareManagerMock{},
		&networkstream.NetworkStreamMock{},
		metricsmanager.NewMetricsMock(),
		nil,
		nil,
		rulepolicy.NewRulePolicyReporter(ruleMock, pmSpy),
		nil,
	)
	factory.listeners = &listenerCache{
		byContainer: map[string]listenerSnapshot{},
		now:         time.Now,
		read: func(pid uint32) (map[uint16]struct{}, error) {
			return map[uint16]struct{}{8443: {}}, nil
		},
	}

	container := makeTestContainer("c-dropped", "ns", "pod", "c", 100)
	container.Runtime.BasicRuntimeMetadata.ContainerPID = 4242
	factory.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: container,
	})

	// An unsolicited SYN to a closed port (9999) with HasDroppedEvents()=true
	ev := &events.EnrichedEvent{
		ContainerID: "c-dropped",
		Event: &eventWithDrops{
			StructEvent: &utils.StructEvent{
				ContainerID: "c-dropped",
				EventType:   utils.NetworkEventType,
				PktType:     utils.HostPktType,
				Proto:       "TCP",
				Pid:         0,
				DstPort:     9999,
			},
		},
	}

	factory.ProcessEvent(ev)

	// Dropped event was accounted for even though the event was dropped as unsolicited ingress
	require.Equal(t, []string{"c-dropped"}, pmSpy.dropped)
}

func TestContainerCallback_EvictionForgetsListeners(t *testing.T) {
	cc := &containercollection.ContainerCollection{}
	factory := NewEventHandlerFactory(
		config.Config{},
		cc,
		&containerprofilemanager.ContainerProfileManagerMock{},
		&dnsmanager.DNSManagerMock{},
		&rulemanager.RuleManagerMock{},
		&malwaremanager.MalwareManagerMock{},
		&networkstream.NetworkStreamMock{},
		metricsmanager.NewMetricsMock(),
		nil,
		nil,
		rulepolicy.NewRulePolicyReporter(&rulemanager.RuleManagerMock{}, &containerprofilemanager.ContainerProfileManagerMock{}),
		nil,
	)
	factory.removalGracePeriod = 20 * time.Millisecond
	factory.listeners = &listenerCache{
		byContainer: map[string]listenerSnapshot{},
		now:         time.Now,
		read: func(pid uint32) (map[uint16]struct{}, error) {
			return map[uint16]struct{}{8443: {}}, nil
		},
	}

	container := makeTestContainer("c-eol", "ns", "pod", "c", 101)
	container.Runtime.BasicRuntimeMetadata.ContainerPID = 5555
	factory.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: container,
	})

	// Populate listeners cache
	listening, known := factory.listeners.listening("c-eol", 5555, 80)
	require.True(t, known)
	require.False(t, listening)

	factory.listeners.mu.Lock()
	_, exists := factory.listeners.byContainer["c-eol"]
	factory.listeners.mu.Unlock()
	require.True(t, exists, "listeners cache has entry for containerID c-eol")

	// Trigger container removal
	factory.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeRemoveContainer,
		Container: container,
	})

	// Verify that after grace period, the entry is forgotten
	require.Eventually(t, func() bool {
		factory.listeners.mu.Lock()
		defer factory.listeners.mu.Unlock()
		_, ok := factory.listeners.byContainer["c-eol"]
		return !ok
	}, time.Second, 5*time.Millisecond, "listeners cache should forget containerID c-eol after container removal")
}
