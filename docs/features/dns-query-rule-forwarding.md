# DNS query rule forwarding

Forward DNS queries and error responses to rule evaluation, so rules can see
DNS exfiltration and tunneling that never gets an answer.

## What changes

The DNS tracer parses every DNS packet on ports 53 and 5353, queries and
responses alike, but historically forwarded only responses that carry at least
one answer record. A query to a domain that returns NXDOMAIN, or that gets no
response at all, never reached a rule. One-way DNS exfiltration works exactly
that way: the data has left in the query name before any answer exists.

With `dnsRuleForwarding.enabled: true` the tracer also forwards:

| Packet | Forwarded | Why |
|---|---|---|
| Response with answers | yes, as before | unchanged path, reaches every DNS consumer |
| Query | yes, **rule-only** | the data carrier; also the only packet when the server never answers |
| NXDOMAIN, SERVFAIL, REFUSED and other error responses | yes, **rule-only** | carry `rcode`, confirm the authoritative server saw the name |
| NOERROR with no answers (NODATA, typically AAAA for an IPv4-only name) | no | repeats the question the query already carried |
| Any name under `.cluster.local.`, `.in-addr.arpa.`, `.ip6.arpa.`, or a configured suffix | no | ndots search-suffix churn and reverse lookups; the bulk of unique names in a cluster |
| Empty name | no | |

With the flag off the behaviour is byte-identical to before.

## Rule-only events

Forwarded queries and error responses are marked rule-only
(`utils.RuleOnlyEvent`). They are delivered to the rule manager and nowhere
else: not to the DNS manager (which issues its own lookup for a name without
addresses), not to the network stream (which would record a query as an
outbound connection), not to metrics, profile learning or third-party
receivers such as the OTel events exporter.

## Rules opt in with `eventType: "dnsQuery"`

Rule-only DNS events keep `dns` as their event type for every accessor and
adapter, but the rule manager selects expressions for them under the alias
`dnsQuery`. Existing `dns` expressions keep matching answered responses only.

This is deliberate: rules such as R0005 (unexpected domain) assume an answered
response, and search-suffix queries like `api.github.com.ec2.internal.` never
enter the learned egress baseline, so routing queries to `dns` expressions would
fire R0005 in every pod on every external lookup. A guard like
`event.qr == 'R'` cannot be added to those rules either, because an older agent
disables any expression that references a field it does not know.

An agent that does not know the alias loads a `dnsQuery` expression without
complaint and never matches it, so rules using it are safe to ship to clusters on
any agent version.

```yaml
ruleExpression:
  - eventType: "dns"        # answered responses, every agent
    expression: |
      event.name.matches('(^|\\.)[0-9a-f]{40,}\\.')
  - eventType: "dnsQuery"   # queries and error responses, agents with forwarding on
    expression: |
      event.qr == 'Q' && event.name.matches('(^|\\.)[0-9a-f]{40,}\\.')
```

Gate `dnsQuery` expressions on `event.qr == 'Q'` when one alert per lookup is
wanted; otherwise the query and its error response both evaluate (the rule
cooldown collapses them when `uniqueId` is the same).

## New CEL fields on DNS events

| Field | Type | Values | Set on |
|---|---|---|---|
| `event.qtype` | string | `A`, `AAAA`, `TXT`, `MX`, `CNAME`, `SRV`, `PTR`, `NS`, `SOA`, ... ; a decimal number such as `10` (NULL) for types without a name | every DNS event |
| `event.qr` | string | `Q` or `R` | every DNS event |
| `event.numAnswers` | int | answer record count | every DNS event |
| `event.rcode` | string | `Success`, `NameError` (NXDOMAIN), `ServerFailure`, `Refused`, `FormatError`, `NotImplemented` | responses only; `has(event.rcode)` is false on a query |

On a non-DNS event the string fields are `""` and `numAnswers` is `0`.

Alerts raised on rule-only events carry `qr`, `qtype`, `numAnswers`, `rcode`
(responses) and `nameserver` (the query destination, or the response source)
in the alert arguments. Alerts on answered responses are unchanged.

## Deduplication

Rule-only DNS events are deduplicated for 5 seconds on
(mount namespace, pid, name, qr, qtype), which absorbs resolver retransmits and
parallel A/AAAA retries without hiding exfiltration chunks, whose names are
unique. Answered responses are never deduplicated, so existing `dns` rules see
every one of them. `eventDedup.enabled: false` or `alertDeduplication.bypass:
true` disables this dedup with the rest.

## Configuration

```json
{
  "dnsRuleForwarding": {
    "enabled": true,
    "excludedSuffixes": ["ec2.internal", "corp.example.com"]
  }
}
```

| Key | Type | Default | Description |
|---|---|---|---|
| `dnsRuleForwarding::enabled` | bool | `false` | Forward queries and error responses to rule evaluation |
| `dnsRuleForwarding::excludedSuffixes` | list | `[]` | Extra name suffixes never forwarded, on top of the built-ins. Normalized to lowercase with leading and trailing dots |

Forwarding requires `runtimeDetectionEnabled`; without it there is no consumer.
Until the Helm chart exposes the key, enable it per cluster through the
`nodeAgent.config.extra` passthrough.

## Cost and metrics

Nothing changes in the kernel or in packet parsing: every packet was already
copied and parsed before the old filter dropped it. Forwarding adds, per
external lookup, roughly one query event (plus one error response for a failed
lookup) to the ordered event queue, process-tree enrichment and one CEL
evaluation per `dnsQuery` rule. The tracer now also skips the packet copy for
every dropped packet, which it previously paid for.

Watch, on a canary node:

- `node_agent.dns.rule_forwarding.total{outcome=answered|query|error_response|skipped_suffix|skipped_nodata|dropped}`
- `node_agent.ebpf.dedup.total{event_type=dns}`
- `node_agent.rule.evaluation.duration{event_type="dnsQuery"}`
- `node_agent.ebpf.events_dropped.total`
- pod CPU and RSS

## Host path

The host watcher (private agent) constructs the same tracer and stays on the
historical filter until it passes the forwarding option itself, after its own
dispatch loop learns to deliver rule-only events to the rule manager only.

## Limits

- DNS over HTTPS or TLS is not inspected.
- Names under the excluded zones are never forwarded, so exfiltration disguised
  as a reverse lookup is out of scope.
- No cross-event state: a rule sees one packet at a time. Counting unique
  subdomains per domain or bytes per window needs a separate aggregation.
