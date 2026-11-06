package statewrites

import (
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The DNS tracer emits one stream, "dns", but the rule loop selects
// expressions by utils.RuleEventType, which renames a rule-only event
// (forwarded query or error response) to "dnsQuery". A write must follow the
// same renaming, or a `dnsQuery` write never fires and a `dns` write fires on
// the queries its own rule expressions never see.

func dnsEnriched(e *utils.StructEvent) *events.EnrichedEvent {
	e.EventType = utils.DnsEventType
	e.ContainerID = "abc"
	e.Comm = "dig"
	e.Pid = 4471
	return &events.EnrichedEvent{Event: e, ContainerID: "abc", PID: 4471}
}

func forwardedQuery() *events.EnrichedEvent {
	return dnsEnriched(&utils.StructEvent{Qr: utils.DNSPktTypeQuery, DNSName: "evil.example.", RuleOnly: true})
}

func errorResponse() *events.EnrichedEvent {
	return dnsEnriched(&utils.StructEvent{Qr: utils.DNSPktTypeResponse, DNSName: "evil.example.", Rcode: "NXDomain", RuleOnly: true})
}

func answeredResponse() *events.EnrichedEvent {
	return dnsEnriched(&utils.StructEvent{Qr: utils.DNSPktTypeResponse, DNSName: "evil.example.", Rcode: "Success", NumAnswers: 1})
}

func dnsWrite(eventType armotypes.EventType, name string) armotypes.StateWrite {
	return armotypes.StateWrite{
		EventType: eventType,
		Scope:     armotypes.StateScopeContainer,
		Name:      name,
		TTL:       "10m",
	}
}

func TestValidate_AcceptsDNSQueryAsDriver(t *testing.T) {
	c, err := Validate(dnsWrite(armotypes.EventTypeDNSQuery, "saw_query"), "R1089", 30*time.Minute)
	require.NoError(t, err, "dnsQuery is the rule-facing name of a rule-only DNS event and must drive a write")
	assert.Equal(t, utils.DnsQueryRuleEventType, c.EventType)
}

func TestApply_RoutesDNSEventsByRuleEventType(t *testing.T) {
	compiled, _, err := ValidateAll([]armotypes.StateWrite{
		dnsWrite(armotypes.EventTypeDNS, "saw_answer"),
		dnsWrite(armotypes.EventTypeDNSQuery, "saw_query"),
	}, "R1089", 30*time.Minute)
	require.NoError(t, err)

	cases := []struct {
		name       string
		event      *events.EnrichedEvent
		written    string
		skipped    string
		provenance armotypes.EventType
	}{
		{"forwarded query", forwardedQuery(), "saw_query", "saw_answer", armotypes.EventTypeDNSQuery},
		{"error response", errorResponse(), "saw_query", "saw_answer", armotypes.EventTypeDNSQuery},
		{"answered response", answeredResponse(), "saw_answer", "saw_query", armotypes.EventTypeDNS},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := testStore(t)
			NewExecutor(store, newFakeEvaluator(), nil).Apply(compiled, "R1089", tc.event, map[string]any{}, time.Now())

			got, ok := store.Get("R1089", "c:abc", tc.written, "")
			require.True(t, ok, "the %s write must fire", tc.written)
			_, ok = store.Get("R1089", "c:abc", tc.skipped, "")
			assert.False(t, ok, "the %s write must not fire", tc.skipped)
			assert.Equal(t, 1, store.Len())

			// Provenance names the stream the rule author wrote, so a reader
			// can tell a remembered query from a remembered answer.
			assert.Equal(t, tc.provenance, got.EventType)
		})
	}
}
