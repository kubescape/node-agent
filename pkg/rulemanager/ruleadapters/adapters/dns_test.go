package adapters

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func dnsFailureArgs(t *testing.T, e *utils.StructEvent) map[string]any {
	t.Helper()
	failure := &types.GenericRuleFailure{}
	NewDnsAdapter().SetFailureMetadata(failure, &events.EnrichedEvent{Event: e}, nil)
	return failure.GetBaseRuntimeAlert().Arguments
}

func TestDnsAdapter_AnsweredResponseArgumentsUnchanged(t *testing.T) {
	args := dnsFailureArgs(t, &utils.StructEvent{
		EventType:  utils.DnsEventType,
		Qr:         utils.DNSPktTypeResponse,
		DNSName:    "example.com.",
		NumAnswers: 1,
		Addresses:  []string{"93.184.216.34"},
		Qtype:      "A",
		Rcode:      "Success",
		SrcIP:      "10.96.0.10",
		DstIP:      "10.244.1.5",
	})
	require.NotNil(t, args)
	assert.Equal(t, "example.com.", args["domain"])
	assert.Equal(t, []string{"93.184.216.34"}, args["addresses"])
	for _, k := range []string{"qr", "qtype", "numAnswers", "rcode", "nameserver"} {
		_, present := args[k]
		assert.False(t, present, "answered responses keep the pre-existing argument set (no %q)", k)
	}
}

func TestDnsAdapter_RuleOnlyQueryArguments(t *testing.T) {
	args := dnsFailureArgs(t, &utils.StructEvent{
		EventType: utils.DnsEventType,
		Qr:        utils.DNSPktTypeQuery,
		DNSName:   "4c6f72656d.exfil.example.",
		Qtype:     "TXT",
		SrcIP:     "10.244.1.5",
		DstIP:     "10.96.0.10",
		RuleOnly:  true,
	})
	assert.Equal(t, "Q", args["qr"])
	assert.Equal(t, "TXT", args["qtype"])
	assert.Equal(t, 0, args["numAnswers"])
	assert.Equal(t, "10.96.0.10", args["nameserver"], "for a query the name server is the destination")
	_, present := args["rcode"]
	assert.False(t, present, "a query has no rcode")
}

func TestDnsAdapter_RuleOnlyErrorResponseArguments(t *testing.T) {
	args := dnsFailureArgs(t, &utils.StructEvent{
		EventType: utils.DnsEventType,
		Qr:        utils.DNSPktTypeResponse,
		DNSName:   "4c6f72656d.exfil.example.",
		Qtype:     "A",
		Rcode:     "NameError",
		SrcIP:     "10.96.0.10",
		DstIP:     "10.244.1.5",
		RuleOnly:  true,
	})
	assert.Equal(t, "R", args["qr"])
	assert.Equal(t, "NameError", args["rcode"])
	assert.Equal(t, "10.96.0.10", args["nameserver"], "for a response the name server is the source")
}
