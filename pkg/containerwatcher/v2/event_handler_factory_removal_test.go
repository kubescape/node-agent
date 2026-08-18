package containerwatcher

import (
	"testing"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerprofilemanager"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/eventreporters/rulepolicy"
	"github.com/kubescape/node-agent/pkg/malwaremanager"
	metricsmanager "github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/networkstream"
	"github.com/kubescape/node-agent/pkg/rulemanager"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// enrichedEventSpy records enriched events dispatched by the factory. It is
// registered as a third-party receiver, which sits behind the same
// container-existence gate as the built-in handlers, so it observes exactly
// what the rule engine would observe.
type enrichedEventSpy struct {
	received []*events.EnrichedEvent
}

func (s *enrichedEventSpy) ReportEnrichedEvent(enrichedEvent *events.EnrichedEvent) {
	s.received = append(s.received, enrichedEvent)
}

func newRemovalTestFactory(t *testing.T, cc *containercollection.ContainerCollection, spy *enrichedEventSpy) *EventHandlerFactory {
	t.Helper()

	thirdParty := &maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]]{}
	receivers := mapset.NewSet[containerwatcher.GenericEventReceiver]()
	receivers.Add(containerwatcher.GenericEventReceiver(spy))
	thirdParty.Set(utils.ExecveEventType, receivers)

	ruleManagerMock := &rulemanager.RuleManagerMock{}
	profileManagerMock := &containerprofilemanager.ContainerProfileManagerMock{}

	return NewEventHandlerFactory(
		config.Config{},
		cc,
		profileManagerMock,
		&dnsmanager.DNSManagerMock{},
		ruleManagerMock,
		&malwaremanager.MalwareManagerMock{},
		&networkstream.NetworkStreamMock{},
		metricsmanager.NewMetricsMock(),
		thirdParty,
		nil,
		rulepolicy.NewRulePolicyReporter(ruleManagerMock, profileManagerMock),
		nil,
	)
}

func makeTestContainer(id, namespace, pod, name string, mntns uint64) *containercollection.Container {
	return &containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{
			BasicRuntimeMetadata: igtypes.BasicRuntimeMetadata{
				ContainerID:   id,
				ContainerName: name,
			},
		},
		Mntns: mntns,
		K8s: containercollection.K8sMetadata{
			BasicK8sMetadata: igtypes.BasicK8sMetadata{
				Namespace:     namespace,
				PodName:       pod,
				ContainerName: name,
			},
		},
	}
}

func makeExecEnrichedEvent(containerID string) *events.EnrichedEvent {
	return &events.EnrichedEvent{
		Event: &utils.StructEvent{
			EventType:   utils.ExecveEventType,
			ContainerID: containerID,
			Comm:        "id",
			Path:        "/usr/bin/id",
		},
		ContainerID: containerID,
	}
}

// TestProcessEvent_DeliversEventForLiveContainer is the baseline: an event for
// a container that is present in the collection must reach the handlers.
func TestProcessEvent_DeliversEventForLiveContainer(t *testing.T) {
	cc := &containercollection.ContainerCollection{}
	spy := &enrichedEventSpy{}
	factory := newRemovalTestFactory(t, cc, spy)

	c := makeTestContainer("live-container", "ns1", "pod1", "app", 1001)
	cc.AddContainer(c)

	factory.ProcessEvent(makeExecEnrichedEvent("live-container"))

	require.Len(t, spy.received, 1, "event for a live container must be dispatched")
	assert.Equal(t, "live-container", spy.received[0].ContainerID)
}

// TestProcessEvent_DeliversEventForJustRemovedContainer pins the end-of-life
// contract: an event that was produced while the container was alive must
// still be dispatched when it is processed shortly AFTER the container's
// removal, because the ordered event queue (50ms collection tick + batching +
// worker pool) delays processing past teardown for a container whose final
// process performs the exec and exits immediately (init containers with a
// terminal exec, ephemeral debug containers).
//
// Evidence: CI run 31846699597 Test_48 — init container "setup"
// (sh -c "sleep 75; /usr/bin/id"): remove processed at 22:44:26, the terminal
// exec event evaluated at ~22:44:26+, zero R0001. Ladder run1 lost all events.
func TestProcessEvent_DeliversEventForJustRemovedContainer(t *testing.T) {
	cc := &containercollection.ContainerCollection{}
	spy := &enrichedEventSpy{}
	factory := newRemovalTestFactory(t, cc, spy)

	c := makeTestContainer("eol-container", "ns1", "pod1", "setup", 1002)
	cc.AddContainer(c)
	// Simulate the container watcher's callback flow on add so the factory can
	// maintain whatever bookkeeping it needs for the removal grace period.
	factory.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: c,
	})

	// The container exits: collection removes it, remove callback fires.
	cc.RemoveContainer("eol-container")
	factory.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeRemoveContainer,
		Container: c,
	})

	// The in-flight terminal exec event is processed only now.
	factory.ProcessEvent(makeExecEnrichedEvent("eol-container"))

	require.Len(t, spy.received, 1,
		"an event emitted during the container's life must be dispatched even when processed after container removal")
	assert.Equal(t, "eol-container", spy.received[0].ContainerID)
}

// TestProcessEvent_DeliversEventForJustRemovedContainer_NoPriorEvent pins the
// worst case observed in ladder run1 (total loss): no earlier event ever
// populated any lazy cache for the container, and the only event of its life
// is the terminal exec arriving after removal. It must still be dispatched.
func TestProcessEvent_DeliversEventForJustRemovedContainer_NoPriorEvent(t *testing.T) {
	cc := &containercollection.ContainerCollection{}
	spy := &enrichedEventSpy{}
	factory := newRemovalTestFactory(t, cc, spy)

	c := makeTestContainer("quiet-eol-container", "ns1", "pod1", "debug", 1003)
	cc.AddContainer(c)
	factory.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: c,
	})
	cc.RemoveContainer("quiet-eol-container")
	factory.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeRemoveContainer,
		Container: c,
	})

	factory.ProcessEvent(makeExecEnrichedEvent("quiet-eol-container"))

	require.Len(t, spy.received, 1,
		"the first-and-only event of a short-lived container must be dispatched after its removal")
}

// TestProcessEvent_RemovedContainerEvictedAfterGrace pins the other side of
// the contract: after the grace window expires, the removed container's info
// is evicted and its events are dropped again (no unbounded tombstone growth).
func TestProcessEvent_RemovedContainerEvictedAfterGrace(t *testing.T) {
	cc := &containercollection.ContainerCollection{}
	spy := &enrichedEventSpy{}
	factory := newRemovalTestFactory(t, cc, spy)
	factory.removalGracePeriod = 50 * time.Millisecond

	c := makeTestContainer("evicted-container", "ns1", "pod1", "setup", 1004)
	cc.AddContainer(c)
	factory.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: c,
	})
	cc.RemoveContainer("evicted-container")
	factory.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeRemoveContainer,
		Container: c,
	})

	assert.Eventually(t, func() bool {
		before := len(spy.received)
		factory.ProcessEvent(makeExecEnrichedEvent("evicted-container"))
		return len(spy.received) == before
	}, 2*time.Second, 25*time.Millisecond,
		"events for a container removed longer than the grace period ago must be dropped")
}

// TestProcessEvent_DropsEventForUnknownContainer guards the negative contract:
// events for containers that were never in the collection stay dropped.
func TestProcessEvent_DropsEventForUnknownContainer(t *testing.T) {
	cc := &containercollection.ContainerCollection{}
	spy := &enrichedEventSpy{}
	factory := newRemovalTestFactory(t, cc, spy)

	factory.ProcessEvent(makeExecEnrichedEvent("never-seen-container"))

	assert.Empty(t, spy.received, "events for unknown containers must not be dispatched")
}
