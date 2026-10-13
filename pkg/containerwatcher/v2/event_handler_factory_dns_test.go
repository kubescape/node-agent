package containerwatcher

import (
	"testing"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerprofilemanager"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/dedupcache"
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

type dnsManagerSpy struct {
	dnsmanager.DNSManagerMock
	names []string
}

func (s *dnsManagerSpy) ReportEvent(e utils.DNSEvent) { s.names = append(s.names, e.GetDNSName()) }

type networkStreamSpy struct {
	networkstream.NetworkStreamMock
	count int
}

func (s *networkStreamSpy) ReportEvent(_ utils.EventType, _ utils.K8sEvent) { s.count++ }

type ruleManagerSpy struct {
	rulemanager.RuleManagerMock
	received []*events.EnrichedEvent
}

func (s *ruleManagerSpy) ReportEnrichedEvent(e *events.EnrichedEvent) {
	s.received = append(s.received, e)
}

type thirdPartySpy struct{ count int }

func (s *thirdPartySpy) ReportEvent(_ utils.EventType, _ utils.K8sEvent) { s.count++ }

type dnsDispatchFixture struct {
	factory     *EventHandlerFactory
	dns         *dnsManagerSpy
	stream      *networkStreamSpy
	rules       *ruleManagerSpy
	thirdParty  *thirdPartySpy
	metrics     *metricsmanager.MetricsMock
	containerID string
}

func newDNSDispatchFixture(t *testing.T, dedup *dedupcache.DedupCache) *dnsDispatchFixture {
	t.Helper()
	cc := &containercollection.ContainerCollection{}
	cc.AddContainer(makeTestContainer("c1", "ns1", "pod1", "app1", 1001))

	f := &dnsDispatchFixture{
		dns:         &dnsManagerSpy{},
		stream:      &networkStreamSpy{},
		rules:       &ruleManagerSpy{},
		thirdParty:  &thirdPartySpy{},
		metrics:     metricsmanager.NewMetricsMock(),
		containerID: "c1",
	}
	thirdParty := &maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]]{}
	thirdParty.Set(utils.DnsEventType, mapset.NewSet[containerwatcher.GenericEventReceiver](f.thirdParty))

	cpm := &containerprofilemanager.ContainerProfileManagerMock{}
	f.factory = NewEventHandlerFactory(
		config.Config{},
		cc,
		cpm,
		f.dns,
		f.rules,
		&malwaremanager.MalwareManagerMock{},
		f.stream,
		f.metrics,
		thirdParty,
		nil,
		rulepolicy.NewRulePolicyReporter(f.rules, cpm),
		dedup,
	)
	return f
}

func dnsEnriched(containerID string, ruleOnly bool, qr utils.DNSPktType, name string, answers int, bucket uint16) *events.EnrichedEvent {
	return dnsEnrichedRcode(containerID, ruleOnly, qr, name, answers, bucket, "")
}

func dnsEnrichedRcode(containerID string, ruleOnly bool, qr utils.DNSPktType, name string, answers int, bucket uint16, rcode string) *events.EnrichedEvent {
	return &events.EnrichedEvent{
		ContainerID:      containerID,
		MountNamespaceID: 1001,
		DedupBucket:      bucket,
		Event: &utils.StructEvent{
			EventType:   utils.DnsEventType,
			ContainerID: containerID,
			Pid:         4242,
			Qr:          qr,
			DNSName:     name,
			NumAnswers:  answers,
			Qtype:       "A",
			Rcode:       rcode,
			RuleOnly:    ruleOnly,
		},
	}
}

func TestEventHandlerFactory_DNSRuleOnlyReachesRuleManagerOnly(t *testing.T) {
	f := newDNSDispatchFixture(t, nil)

	f.factory.ProcessEvent(dnsEnriched(f.containerID, true, utils.DNSPktTypeQuery, "4c6f72656d.exfil.example.", 0, 1))

	require.Len(t, f.rules.received, 1, "rule manager receives the forwarded query")
	assert.True(t, utils.IsRuleOnlyEvent(f.rules.received[0].Event))
	assert.Empty(t, f.dns.names, "DNS manager must not see a query (it would issue its own lookup)")
	assert.Equal(t, 0, f.stream.count, "network stream must not record a query as outbound")
	assert.Equal(t, 0, f.thirdParty.count, "third-party receivers must not see rule-only events")
	assert.Equal(t, 0, f.metrics.EventCounter.Get(utils.DnsEventType), "rule-only events do not inflate the dns event metric")
}

func TestEventHandlerFactory_DNSAnsweredReachesEveryHandler(t *testing.T) {
	f := newDNSDispatchFixture(t, nil)

	f.factory.ProcessEvent(dnsEnriched(f.containerID, false, utils.DNSPktTypeResponse, "example.com.", 1, 1))

	assert.Len(t, f.rules.received, 1)
	assert.Equal(t, []string{"example.com."}, f.dns.names)
	assert.Equal(t, 1, f.stream.count)
	assert.Equal(t, 1, f.thirdParty.count)
	assert.Equal(t, 1, f.metrics.EventCounter.Get(utils.DnsEventType))
}

func TestEventHandlerFactory_DNSDedupAppliesToRuleOnlyEventsOnly(t *testing.T) {
	f := newDNSDispatchFixture(t, dedupcache.NewDedupCache(10))

	// Two identical forwarded queries within the TTL: the second is a
	// duplicate and reaches nobody.
	f.factory.ProcessEvent(dnsEnriched(f.containerID, true, utils.DNSPktTypeQuery, "a.exfil.example.", 0, 1))
	f.factory.ProcessEvent(dnsEnriched(f.containerID, true, utils.DNSPktTypeQuery, "a.exfil.example.", 0, 2))
	require.Len(t, f.rules.received, 1, "duplicate rule-only event is not delivered")
	assert.False(t, f.rules.received[0].Duplicate)

	// A different name, and the same name as a response, are distinct keys.
	f.factory.ProcessEvent(dnsEnriched(f.containerID, true, utils.DNSPktTypeQuery, "b.exfil.example.", 0, 2))
	f.factory.ProcessEvent(dnsEnriched(f.containerID, true, utils.DNSPktTypeResponse, "a.exfil.example.", 0, 2))
	assert.Len(t, f.rules.received, 3)

	// Answered responses are never deduplicated, so the existing dns rules
	// keep seeing every one of them.
	before := len(f.rules.received)
	f.factory.ProcessEvent(dnsEnriched(f.containerID, false, utils.DNSPktTypeResponse, "example.com.", 1, 3))
	f.factory.ProcessEvent(dnsEnriched(f.containerID, false, utils.DNSPktTypeResponse, "example.com.", 1, 3))
	assert.Len(t, f.rules.received, before+2)
	for _, e := range f.rules.received[before:] {
		assert.False(t, e.Duplicate, "answered response must never be marked duplicate")
	}
	assert.Equal(t, []string{"example.com.", "example.com."}, f.dns.names)
}

// A process whose resolv.conf lists two nameservers gets SERVFAIL from the
// first and NXDOMAIN from the retry within the dedup TTL, for the same name and
// type. The NXDOMAIN must still reach a rule gated on event.rcode, while a
// retransmitted identical error response is still absorbed.
func TestEventHandlerFactory_DNSDedupKeepsDistinctResponseCodes(t *testing.T) {
	f := newDNSDispatchFixture(t, dedupcache.NewDedupCache(10))

	f.factory.ProcessEvent(dnsEnrichedRcode(f.containerID, true, utils.DNSPktTypeResponse, "a.exfil.example.", 0, 1, "ServerFailure"))
	f.factory.ProcessEvent(dnsEnrichedRcode(f.containerID, true, utils.DNSPktTypeResponse, "a.exfil.example.", 0, 2, "NameError"))
	f.factory.ProcessEvent(dnsEnrichedRcode(f.containerID, true, utils.DNSPktTypeResponse, "a.exfil.example.", 0, 3, "NameError"))

	require.Len(t, f.rules.received, 2, "SERVFAIL and NXDOMAIN are delivered, the repeated NXDOMAIN is not")
	var rcodes []string
	for _, e := range f.rules.received {
		assert.False(t, e.Duplicate)
		rcodes = append(rcodes, e.Event.(utils.DNSEvent).GetRcode())
	}
	assert.Equal(t, []string{"ServerFailure", "NameError"}, rcodes)
}

func TestComputeEventDedupKey_DNS(t *testing.T) {
	ruleOnly := dnsEnriched("c1", true, utils.DNSPktTypeQuery, "a.exfil.example.", 0, 1)
	key, ttl, ok := computeEventDedupKey(ruleOnly)
	require.True(t, ok)
	assert.Equal(t, dedupTTLDNS, ttl)
	assert.NotZero(t, key)

	answered := dnsEnriched("c1", false, utils.DNSPktTypeResponse, "example.com.", 1, 1)
	_, _, ok = computeEventDedupKey(answered)
	assert.False(t, ok, "answered responses are not deduplicated")
}
