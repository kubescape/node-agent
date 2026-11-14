package containerwatcher

import (
	"testing"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerprofilemanager"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/eventreporters/rulepolicy"
	"github.com/kubescape/node-agent/pkg/malwaremanager"
	metricsmanager "github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/networkstream"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// customEventType has no built-in handler: it stands for the event type of a
// third-party tracer registered through GetThirdPartyTracers.
const customEventType utils.EventType = "custom"

func newThirdPartyFactory(t *testing.T, receivers ...containerwatcher.GenericEventReceiver) (*EventHandlerFactory, *ruleManagerSpy) {
	t.Helper()
	cc := &containercollection.ContainerCollection{}
	cc.AddContainer(makeTestContainer("c1", "ns1", "pod1", "app1", 1001))

	thirdParty := &maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]]{}
	thirdParty.Set(customEventType, mapset.NewSet(receivers...))

	rules := &ruleManagerSpy{}
	cpm := &containerprofilemanager.ContainerProfileManagerMock{}
	factory := NewEventHandlerFactory(
		config.Config{},
		cc,
		cpm,
		&dnsmanager.DNSManagerMock{},
		rules,
		&malwaremanager.MalwareManagerMock{},
		&networkstream.NetworkStreamMock{},
		metricsmanager.NewMetricsMock(),
		thirdParty,
		nil,
		rulepolicy.NewRulePolicyReporter(rules, cpm),
		nil,
	)
	return factory, rules
}

func customEnriched(containerID string) *events.EnrichedEvent {
	return &events.EnrichedEvent{
		ContainerID:      containerID,
		MountNamespaceID: 1001,
		Event: &utils.StructEvent{
			EventType:   customEventType,
			ContainerID: containerID,
			Pid:         4242,
		},
	}
}

func TestEventHandlerFactory_CustomEventTypeReachesThirdPartyReceivers(t *testing.T) {
	plain := &thirdPartySpy{}
	enriched := &ruleManagerSpy{}
	factory, builtinRules := newThirdPartyFactory(t, plain, enriched)

	factory.ProcessEvent(customEnriched("c1"))

	assert.Equal(t, 1, plain.count, "EventReceiver registered for the custom type gets the event")
	require.Len(t, enriched.received, 1, "EnrichedEventReceiver registered for the custom type gets the event")
	assert.Equal(t, customEventType, enriched.received[0].Event.GetEventType())
	assert.Empty(t, builtinRules.received, "built-in handlers are not called for a type they don't handle")
}

func TestEventHandlerFactory_CustomEventTypeUnknownContainerIsDropped(t *testing.T) {
	plain := &thirdPartySpy{}
	factory, _ := newThirdPartyFactory(t, plain)

	factory.ProcessEvent(customEnriched("unknown"))

	assert.Equal(t, 0, plain.count, "events without container attribution are still dropped")
}
