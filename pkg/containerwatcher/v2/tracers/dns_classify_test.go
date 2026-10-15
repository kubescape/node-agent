package tracers

import (
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func dnsStruct(qr utils.DNSPktType, name string, answers int, rcode string) *utils.StructEvent {
	return &utils.StructEvent{
		EventType:  utils.DnsEventType,
		Qr:         qr,
		DNSName:    name,
		NumAnswers: answers,
		Rcode:      rcode,
		Qtype:      "A",
	}
}

func TestClassifyDNS(t *testing.T) {
	fwd := newDNSForwarding([]string{"EC2.internal"})

	tests := []struct {
		name     string
		event    *utils.StructEvent
		fwd      *dnsForwarding
		forward  bool
		ruleOnly bool
		outcome  dnsOutcome
	}{
		// flag off: the historical filter, byte for byte
		{"off: answered response passes", dnsStruct(utils.DNSPktTypeResponse, "a.example.", 1, "Success"), nil, true, false, dnsOutcomeAnswered},
		{"off: query dropped", dnsStruct(utils.DNSPktTypeQuery, "a.example.", 0, ""), nil, false, false, dnsOutcomeDropped},
		{"off: NXDOMAIN dropped", dnsStruct(utils.DNSPktTypeResponse, "a.example.", 0, "NameError"), nil, false, false, dnsOutcomeDropped},
		{"off: NODATA dropped", dnsStruct(utils.DNSPktTypeResponse, "a.example.", 0, "Success"), nil, false, false, dnsOutcomeDropped},

		// flag on
		{"on: answered response passes, not rule-only", dnsStruct(utils.DNSPktTypeResponse, "a.example.", 2, "Success"), fwd, true, false, dnsOutcomeAnswered},
		{"on: query forwarded rule-only", dnsStruct(utils.DNSPktTypeQuery, "4c6f72656d.exfil.example.", 0, ""), fwd, true, true, dnsOutcomeQuery},
		{"on: NXDOMAIN forwarded rule-only", dnsStruct(utils.DNSPktTypeResponse, "4c6f72656d.exfil.example.", 0, "NameError"), fwd, true, true, dnsOutcomeErrorResponse},
		{"on: SERVFAIL forwarded rule-only", dnsStruct(utils.DNSPktTypeResponse, "a.example.", 0, "ServerFailure"), fwd, true, true, dnsOutcomeErrorResponse},
		{"on: REFUSED forwarded rule-only", dnsStruct(utils.DNSPktTypeResponse, "a.example.", 0, "Refused"), fwd, true, true, dnsOutcomeErrorResponse},
		{"on: NODATA skipped", dnsStruct(utils.DNSPktTypeResponse, "a.example.", 0, "Success"), fwd, false, false, dnsOutcomeSkippedNodata},
		{"on: empty name dropped", dnsStruct(utils.DNSPktTypeQuery, "", 0, ""), fwd, false, false, dnsOutcomeDropped},

		// built-in suffix exclusions, mixed case, queries and error responses alike
		{"on: svc.cluster.local query skipped", dnsStruct(utils.DNSPktTypeQuery, "api.stripe.com.default.svc.cluster.local.", 0, ""), fwd, false, false, dnsOutcomeSkippedSuffix},
		{"on: cluster.local NXDOMAIN skipped", dnsStruct(utils.DNSPktTypeResponse, "api.stripe.com.svc.Cluster.Local.", 0, "NameError"), fwd, false, false, dnsOutcomeSkippedSuffix},
		{"on: in-addr.arpa skipped", dnsStruct(utils.DNSPktTypeQuery, "4.3.2.1.in-addr.arpa.", 0, ""), fwd, false, false, dnsOutcomeSkippedSuffix},
		{"on: ip6.arpa skipped", dnsStruct(utils.DNSPktTypeQuery, "1.0.0.0.ip6.arpa.", 0, ""), fwd, false, false, dnsOutcomeSkippedSuffix},
		{"on: user suffix skipped", dnsStruct(utils.DNSPktTypeQuery, "api.stripe.com.ec2.internal.", 0, ""), fwd, false, false, dnsOutcomeSkippedSuffix},
		{"on: suffix must match on a label boundary", dnsStruct(utils.DNSPktTypeQuery, "notcluster.local.", 0, ""), fwd, true, true, dnsOutcomeQuery},
		{"on: answered response to an excluded name still passes", dnsStruct(utils.DNSPktTypeResponse, "kube-dns.kube-system.svc.cluster.local.", 1, "Success"), fwd, true, false, dnsOutcomeAnswered},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			forward, ruleOnly, outcome := classifyDNS(tc.event, tc.fwd)
			assert.Equal(t, tc.forward, forward, "forward")
			assert.Equal(t, tc.ruleOnly, ruleOnly, "ruleOnly")
			assert.Equal(t, tc.outcome, outcome, "outcome")
		})
	}
}

func TestWithDNSRuleForwarding(t *testing.T) {
	off := NewDNSTracer(nil, nil, nil, nil, nil, nil, WithDNSRuleForwarding(config.DNSRuleForwardingConfig{}))
	assert.Nil(t, off.forwarding, "disabled config must leave forwarding off")

	on := NewDNSTracer(nil, nil, nil, nil, nil, nil, WithDNSRuleForwarding(config.DNSRuleForwardingConfig{
		Enabled:          true,
		ExcludedSuffixes: []string{".corp.example.", "ignored-empty"},
	}))
	require.NotNil(t, on.forwarding)
	assert.Equal(t, append(append([]string{}, builtinExcludedDNSSuffixes...), ".corp.example.", ".ignored-empty."), on.forwarding.excludedSuffixes)

	none := NewDNSTracer(nil, nil, nil, nil, nil, nil)
	assert.Nil(t, none.forwarding, "no option keeps the historical behaviour")
}

// TestClassifyDNS_DatasourceEvent runs the classifier over a real datasource
// packet, the way the subscribe callback does, and checks the forwarded copy
// is marked rule-only and independent of the original buffer.
func TestClassifyDNS_DatasourceEvent(t *testing.T) {
	ds, err := datasource.New(datasource.TypeSingle, "dns")
	require.NoError(t, err)
	qrAcc, err := ds.AddField("qr_raw", api.Kind_Bool)
	require.NoError(t, err)
	nameAcc, err := ds.AddField("name", api.Kind_String)
	require.NoError(t, err)
	numAcc, err := ds.AddField("num_answers", api.Kind_Int32)
	require.NoError(t, err)
	rcodeAcc, err := ds.AddField("rcode", api.Kind_String)
	require.NoError(t, err)
	qtypeAcc, err := ds.AddField("qtype", api.Kind_String)
	require.NoError(t, err)

	data, err := ds.NewPacketSingle()
	require.NoError(t, err)
	t.Cleanup(func() { ds.Release(data) })
	require.NoError(t, qrAcc.PutBool(data, true))
	require.NoError(t, nameAcc.PutString(data, "4c6f72656d.exfil.example."))
	require.NoError(t, numAcc.PutInt32(data, 0))
	require.NoError(t, rcodeAcc.PutString(data, "NameError"))
	require.NoError(t, qtypeAcc.PutString(data, "A"))

	view := &utils.DatasourceEvent{Datasource: ds, Data: data, EventType: utils.DnsEventType}
	forward, ruleOnly, outcome := classifyDNS(view, newDNSForwarding(nil))
	assert.True(t, forward)
	assert.True(t, ruleOnly)
	assert.Equal(t, dnsOutcomeErrorResponse, outcome)

	copied := &utils.DatasourceEvent{Datasource: ds, Data: ds.DeepCopy(data), EventType: utils.DnsEventType, RuleOnly: ruleOnly}
	assert.True(t, utils.IsRuleOnlyEvent(copied))
	assert.Equal(t, utils.DnsQueryRuleEventType, utils.RuleEventType(copied))
	assert.Equal(t, "NameError", copied.GetRcode())
	assert.Equal(t, "A", copied.GetQtype())

	// Mutating the original must not change the copy.
	require.NoError(t, nameAcc.PutString(data, "other.example."))
	assert.Equal(t, "4c6f72656d.exfil.example.", copied.GetDNSName())

	// A query never reports an rcode, even if the pooled buffer holds one.
	require.NoError(t, qrAcc.PutBool(data, false))
	assert.Equal(t, "", view.GetRcode())
	assert.False(t, utils.IsRuleOnlyEvent(view), "the uncopied view is never marked")
}
