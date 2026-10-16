package cel

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/ebpf/events"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/require"
)

func dnsQueryEvent(name, qtype string) *utils.StructEvent {
	return &utils.StructEvent{
		EventType: utils.DnsEventType,
		Qr:        utils.DNSPktTypeQuery,
		DNSName:   name,
		Qtype:     qtype,
		Comm:      "dig",
		RuleOnly:  true,
	}
}

func dnsErrorResponse(name, qtype, rcode string) *utils.StructEvent {
	e := dnsQueryEvent(name, qtype)
	e.Qr = utils.DNSPktTypeResponse
	e.Rcode = rcode
	return e
}

func dnsAnsweredResponse(name string) *utils.StructEvent {
	return &utils.StructEvent{
		EventType:  utils.DnsEventType,
		Qr:         utils.DNSPktTypeResponse,
		DNSName:    name,
		Qtype:      "A",
		Rcode:      "Success",
		NumAnswers: 1,
		Addresses:  []string{"93.184.216.34"},
		Comm:       "curl",
	}
}

// evalDNS evaluates expr under the given rule event type, the way a rule
// expression declares it in YAML.
func evalDNS(t *testing.T, e *utils.StructEvent, ruleEventType utils.EventType, expr string) bool {
	t.Helper()
	return evalTTYEvent(t, e, ruleEventType, expr)
}

func TestCEL_DNSFields(t *testing.T) {
	q := dnsQueryEvent("4c6f72656d.exfil.example.", "TXT")
	require.True(t, evalDNS(t, q, utils.DnsQueryRuleEventType, `event.qtype == 'TXT'`))
	require.True(t, evalDNS(t, q, utils.DnsQueryRuleEventType, `event.qr == 'Q'`))
	require.True(t, evalDNS(t, q, utils.DnsQueryRuleEventType, `event.numAnswers == 0`))
	require.False(t, evalDNS(t, q, utils.DnsQueryRuleEventType, `has(event.rcode)`), "a query carries no rcode")
	require.True(t, evalDNS(t, q, utils.DnsQueryRuleEventType, `event.rcode == ''`), "reading rcode on a query is safe and empty")

	nx := dnsErrorResponse("4c6f72656d.exfil.example.", "A", "NameError")
	require.True(t, evalDNS(t, nx, utils.DnsQueryRuleEventType, `has(event.rcode) && event.rcode == 'NameError'`))
	require.True(t, evalDNS(t, nx, utils.DnsQueryRuleEventType, `event.qr == 'R' && event.numAnswers == 0`))

	ans := dnsAnsweredResponse("example.com.")
	require.True(t, evalDNS(t, ans, utils.DnsEventType, `event.qtype == 'A' && event.qr == 'R' && event.numAnswers == 1`))
	require.True(t, evalDNS(t, ans, utils.DnsEventType, `has(event.rcode) && event.rcode == 'Success'`))
}

func TestCEL_DNSFields_NonDNSEventIsEmpty(t *testing.T) {
	exec := &utils.StructEvent{EventType: utils.ExecveEventType, Comm: "sh"}
	require.True(t, evalDNS(t, exec, utils.ExecveEventType, `event.qtype == '' && event.qr == '' && event.numAnswers == 0`))
	require.False(t, evalDNS(t, exec, utils.ExecveEventType, `has(event.rcode)`))

	// The datasource-backed event is what runs in production; its DNS
	// accessors must not read gadget fields that an exec datasource does not
	// carry, and qr must not default to Q.
	ds := newDatasourceExecEvent(t, utils.ExecveEventType, ttyDSFields{})
	require.True(t, evalTTYEvent(t, ds, utils.ExecveEventType, `event.qtype == '' && event.qr == '' && event.rcode == '' && event.numAnswers == 0`))
	require.False(t, evalTTYEvent(t, ds, utils.ExecveEventType, `has(event.rcode)`))
}

// TestCEL_DNSQueryAliasRouting pins the opt-in contract: a forwarded (rule-only)
// DNS event matches only expressions declared for "dnsQuery", and an answered
// response matches only expressions declared for "dns".
func TestCEL_DNSQueryAliasRouting(t *testing.T) {
	c := newTestCEL(t)
	require.NoError(t, c.registerExpression(`true`))
	require.NoError(t, c.registerExpression(`false`))

	// EvaluateRuleWithContext only evaluates expressions declared for the
	// selected event type (and returns true when none is, which the rule
	// manager guards against by filtering first). Contradicting expressions
	// under the two types therefore reveal which one was selected.
	queryTrueDNSFalse := []typesv1.RuleExpression{
		{EventType: utils.DnsQueryRuleEventType, Expression: `true`},
		{EventType: utils.DnsEventType, Expression: `false`},
	}
	queryFalseDNSTrue := []typesv1.RuleExpression{
		{EventType: utils.DnsQueryRuleEventType, Expression: `false`},
		{EventType: utils.DnsEventType, Expression: `true`},
	}

	forwarded := &events.EnrichedEvent{Event: dnsQueryEvent("4c6f72656d.exfil.example.", "A")}
	ok, err := c.EvaluateRule(forwarded, queryTrueDNSFalse)
	require.NoError(t, err)
	require.True(t, ok, "rule-only event selects the dnsQuery expression")
	ok, err = c.EvaluateRule(forwarded, queryFalseDNSTrue)
	require.NoError(t, err)
	require.False(t, ok, "rule-only event ignores the dns expression")

	answered := &events.EnrichedEvent{Event: dnsAnsweredResponse("4c6f72656d.exfil.example.")}
	ok, err = c.EvaluateRule(answered, queryFalseDNSTrue)
	require.NoError(t, err)
	require.True(t, ok, "answered response selects the dns expression")
	ok, err = c.EvaluateRule(answered, queryTrueDNSFalse)
	require.NoError(t, err)
	require.False(t, ok, "answered response ignores the dnsQuery expression")

	// The eval context still names the tracer event type, so rules and
	// libraries that switch on eventType keep working.
	ctx := c.CreateEvalContext(forwarded)
	require.Equal(t, "dns", ctx["eventType"])
}

func TestRuleEventType(t *testing.T) {
	require.Equal(t, utils.DnsQueryRuleEventType, utils.RuleEventType(dnsQueryEvent("a.example.", "A")))
	require.Equal(t, utils.DnsEventType, utils.RuleEventType(dnsAnsweredResponse("a.example.")))
	exec := &utils.StructEvent{EventType: utils.ExecveEventType, RuleOnly: true}
	require.Equal(t, utils.ExecveEventType, utils.RuleEventType(exec), "the alias is DNS-specific")
}
