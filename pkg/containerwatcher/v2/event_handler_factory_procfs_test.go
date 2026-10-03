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
)

type procfsExecCall struct {
	containerID string
	path        string
	argv        []string
}

type procfsProfileManagerSpy struct {
	containerprofilemanager.ContainerProfileManagerMock
	reported []procfsExecCall
}

func (s *procfsProfileManagerSpy) ReportProcfsExec(containerID string, path string, argv []string) {
	s.reported = append(s.reported, procfsExecCall{
		containerID: containerID,
		path:        path,
		argv:        argv,
	})
}

func TestEventHandlerFactory_ProcfsAmbiguousAttribution(t *testing.T) {
	cc := &containercollection.ContainerCollection{}
	c1 := makeTestContainer("c1", "ns1", "pod1", "app1", 1001)
	c2 := makeTestContainer("c2", "ns1", "pod1", "app2", 1002)
	cc.AddContainer(c1)
	cc.AddContainer(c2)

	spy := &procfsProfileManagerSpy{}
	ruleManagerMock := &rulemanager.RuleManagerMock{}
	thirdParty := &maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]]{}

	factory := NewEventHandlerFactory(
		config.Config{},
		cc,
		spy,
		&dnsmanager.DNSManagerMock{},
		ruleManagerMock,
		&malwaremanager.MalwareManagerMock{},
		&networkstream.NetworkStreamMock{},
		metricsmanager.NewMetricsMock(),
		thirdParty,
		nil,
		rulepolicy.NewRulePolicyReporter(ruleManagerMock, spy),
		nil,
	)

	// Case 1: Unambiguous procfs event (mount namespace matched) -> reported to CPM
	unambiguousEvent := &events.EnrichedEvent{
		ContainerID: "c1",
		Event: &events.ProcfsEvent{
			Type:               igtypes.NORMAL,
			Timestamp:          igtypes.Time(time.Now().UnixNano()),
			ContainerID:        "c1",
			Path:               "/bin/sh",
			Argv:               []string{"/bin/sh", "-c", "echo hi"},
			AmbiguousContainer: false,
		},
	}
	factory.ProcessEvent(unambiguousEvent)
	assert.Len(t, spy.reported, 1)
	assert.Equal(t, "c1", spy.reported[0].containerID)
	assert.Equal(t, "/bin/sh", spy.reported[0].path)

	// Case 2: Ambiguous procfs event (fell back to shared netns in multi-container pod) -> skipped
	ambiguousEvent := &events.EnrichedEvent{
		ContainerID: "c2",
		Event: &events.ProcfsEvent{
			Type:               igtypes.NORMAL,
			Timestamp:          igtypes.Time(time.Now().UnixNano()),
			ContainerID:        "c2",
			Path:               "/bin/sidecar",
			Argv:               []string{"/bin/sidecar"},
			AmbiguousContainer: true,
		},
	}
	factory.ProcessEvent(ambiguousEvent)
	assert.Len(t, spy.reported, 1, "ambiguous procfs event must not be reported to CPM")
}
