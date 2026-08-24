# CEL rule state store

Gives a CEL rule memory across events, so a detection can span more than one
event: remember something on `exec`, alert on `network`. Without it, every rule
is a pure predicate over a single event and multi-step behaviour — a process
launched from a mount that later connects out, a webshell chain, create/exec/
delete of a pod — cannot be expressed at all.

Design: `shared-designs-and-docs/projects/2026-07-28-cel-rule-state-store/spec.md`.

> **Status: proven end-to-end on a cluster.** Verified against real eBPF events
> on kind by `Test_36_CelStateStoreCorrelation`: a rule that writes on `exec` and
> alerts on `network` fires, carries the remembered `value:` through to its
> message, and a negative control confirms it is not firing spuriously.
>
> **Deployment prerequisite:** the `Rules` CRD must declare `stateWrites`. The
> canonical CRD ships from **`kubescape/helm-charts`**, and until the property is
> added there the API server silently strips the clause — rules load cleanly and
> never fire, with no error anywhere. The copy in `tests/chart/crds/` is fixed;
> helm-charts is a separate, required change.

## Writing state

A rule declares what it remembers in a `stateWrites:` block. Each entry is driven
by one event type, which **need not** be an event type the rule alerts on:

```yaml
id: R1089
stateWrites:
  - eventType: exec                     # the stream that drives this write
    when: "<a CEL bool guard>"          # optional; absent means always write
    scope: container                    # container | pod | node
    name: mount_exec                    # a literal, never an expression
    key: "string(event.pid)"            # optional CEL string: who the fact is about
    value:                              # optional extras, CEL expression strings
      argv: "event.args"
    ttl: 10m                            # clamped to the configured maxTtl
expressions:
  ruleExpression:
    - eventType: network                # alerts on a DIFFERENT stream
      expression: |
        state.has("mount_exec", string(event.pid)) && !net.is_private_ip(event.dstIP)
```

`name` is a literal rather than an expression on purpose: it stays statically
analysable and is safe to use as a metric label.

### Writes are declarative, not a CEL setter

There is no `state.set(...)` function, deliberately. A setter inside a predicate
would be skipped by boolean short-circuiting, could be reordered by the static
optimiser, and could never express "remember this **without** alerting" — which
is exactly what the first leg of a cross-event rule needs.

### Writes run after the predicate

For a given event, the rule's predicate is evaluated first and the writes second.
So a predicate only ever sees state from **earlier** events. Otherwise a rule
that reads and writes the same name on the same event type would satisfy itself
from its own write.

### What suppresses a write

| Condition | Writes still run? |
|---|---|
| Rule disabled, or does not apply to this context | no |
| `profileDependency: Required` and no profile | no |
| Pre-filter excluded the event | no |
| Rule policy suppressed it | no |
| **Alert cooldown** | **yes** |
| **Predicate returned false** | **yes** |
| Store at capacity | no — write rejected, `state_write_rejected_total` |

Cooldown suppresses the *alert*, never the write: writes are evidence gathering,
and dropping them would break the next leg of the chain.

### Validation happens at load

An unknown event type, `eventType: all` (a binding wildcard, not a stream),
`scope: identity` (operator-only), a bad or non-positive TTL, or a `_`-prefixed
name or value key is rejected when the rule loads. Every one of those mistakes
would otherwise produce a rule that loads cleanly and silently never fires.

A rule with a malformed clause is degraded to non-correlating and logged; it does
not stop the other rules in the CRD from evaluating.

### Bounds

Over-capacity writes are **rejected, never satisfied by evicting** another
entry — eviction would let one container disable detection for its neighbours.
The per-scope cap is exact; the node-wide ceiling is approximate under
concurrency. At the ceiling a write first tries to reclaim expired entries, but at
most one such sweep runs per `sweepInterval` across all writers — otherwise every
write at a full store would walk all 16 shards under their locks, stalling the
whole rule loop at the busiest possible moment. A write arriving between sweeps is
treated as though the sweep freed nothing, which is what it would have found. Host processes share one `c:__host__` bucket with its own larger cap,
since it holds the whole node's process space and gets no removal purge; node scope
takes that same larger cap for the same reason.

## Reading state

Four functions, on a `state` receiver:

```cel
state.has(name)                  // bool  — for a fact about the whole scope
state.has(name, key)             // bool  — for a fact about one subject
state.get(name)                  // map   — empty map on a miss, never an error
state.get(name, key)             // map
state.has_ancestor(name)         // bool  — any ancestor PID carries the marker
state.get_ancestor(name)         // map   — the NEAREST matching ancestor
```

`name` is what kind of fact ("mount_exec"); `key` is who it is about, usually
`string(event.pid)`. A read takes **no scope argument**: state is rule-private,
so the name already determines its scope from the rule's own `stateWrites`.

`state.get` on a miss returns an **empty map**, so guard provenance access with
`state.has` — `state.get("x", k)._pid` on a miss is a "no such key" error, and
that error fails the whole predicate:

```cel
state.has("mount_exec", string(event.ppid)) &&
  state.get("mount_exec", string(event.ppid))._ts < timestamp
```

### What `state.get` returns

Engine-stamped provenance uses reserved `_`-prefixed keys; the rule's own
`value:` entries sit alongside them at the top level. Author keys may not begin
with `_`, so they can never shadow provenance.

| Key | Type | Meaning |
|---|---|---|
| `_ts` | timestamp | When the remembered event happened. Compare against `timestamp`. |
| `_eventType` | string | The event stream that wrote the entry. |
| `_container` | string | The scope ID the entry lives under. |
| `_pid` / `_ppid` | uint | Process and parent PID. |
| `_comm` / `_pcomm` | string | Process and parent command name. |
| `_exe` | string | Executable path. |
| `_cwd` | string | Working directory. |

### The ancestor functions assume a PID key

`has_ancestor` / `get_ancestor` probe each ancestor PID in turn, so they only
find entries whose `key` was a PID. That is an authoring contract, not something
the engine can check — write `key: string(event.pid)` for any name you intend to
read this way.

They work identically for host and containerised processes.

### Why `state` is a variable, not a function namespace

Unlike `process.*` or `net.*`, `state` is a **variable** with member functions.
cel-go hands a function binding only its arguments, never the surrounding
context, so a global `state.has` could not know which rule or which container it
was evaluating for.

That is also the security property: the rule ID, the scope IDs and the ancestor
list live in the receiver, and no CEL syntax supplies or overrides them. Reading
another rule's state or a neighbouring container's state is not merely forbidden
— it is inexpressible.

## `timestamp` — the resolved event time

A top-level CEL variable (not an `event` field) holding the authoritative time
for the event being evaluated:

```cel
timestamp                          // a CEL timestamp
timestamp - duration("5m")         // arithmetic and comparison work
```

It is the event's **kernel** timestamp where the event carries one, falling back
to node-agent's enrichment time only when that is zero.

Two reasons it is defined this way:

**Kernel time, not observation time.** Events are processed by a concurrent
worker pool, so the order node-agent *sees* events is not the order they
*happened*. Any ordering comparison has to be against when things happened or it
is meaningless.

**One source of truth.** The same function populates both this variable and the
timestamp stamped onto stored state entries. If the two could disagree, an
ordering guard would be comparing different clocks and would silently never
fire — the worst failure mode for a detection rule.

It is a top-level variable rather than `event.timestamp` because the `event`
field getters receive a wrapper around the raw event and cannot see
node-agent's enrichment time; an event field would therefore have to be a
second, divergent source of truth.

### Timezone

`string(timestamp)` renders in the node's local zone, so the offset in the text
depends on where the agent runs. Comparisons are instant-based and unaffected.
Assert on instants, not on rendered text.

## Correlation evidence on the alert

When a rule fires, the state entries its predicate **actually read** are attached
to the alert as `correlations[]`, so the alert describes both ends of the chain.
Without it, an exec-then-egress alert would say only "a process made an outbound
connection" and drop the exec that makes it interesting.

Each entry carries `name`, `eventType`, `timestamp`, `scope`, `key`, the
remembered `process`, and any author `values`. Only hits are recorded — a miss is
not evidence of anything — and the record is reset per rule, so one rule never
cites another's entries.

**Correlation enriches an incident; it does not re-key it.** `InfectedPID` and
`RuntimeProcessDetails` continue to describe the *triggering* event, so backend
incident grouping is unchanged. An alert with no correlations serializes exactly
as before, with no `correlations` key.

`message` and `uniqueId` are evaluated against the predicate's own context, so
`state.get()` in a message resolves against the same entries the predicate
matched — and `uniqueId` can be derived from the join key, which is what lets
cooldown collapse both legs of a bidirectional rule into one alert.

## Configuration

```yaml
celStateStore:
  enabled: true
  maxSize: 100000               # node-wide ceiling (approximate under concurrency)
  maxEntriesPerContainer: 256   # exact, per container
  maxEntriesForHost: 4096       # the c:__host__ bucket
  maxTtl: 30m                   # every rule's ttl is clamped to this
  sweepInterval: 30s
  ancestorMaxDepth: 8           # probes per has_ancestor call
```

Disabling it makes writes no-ops and every read a miss, so correlation rules stop
firing while ordinary rules are unaffected.

A container's entries are purged as soon as the container is removed, rather than
waiting for TTL. A **pod** bucket is purged once the pod's *last* container is
removed — it cannot go earlier, because pod-scoped state exists precisely to
outlive any one container in the pod. That check runs on the same 10-minute timer
as the rest of the pod-level cleanup, so a pod bucket can outlive its pod by up to
ten minutes before being reclaimed.

The **host and node** buckets get no purge at all — they are node-wide and belong
to no workload, so they rely on TTL, which is why their cap is larger.

Pod scope shares the per-container cap, and that cap covers the whole pod rather
than each container in it. Pod scope is meant for facts about the pod as a unit; if
a real workload needs more room, `state_write_rejected_total{reason="scope_cap"}`
is what will say so.

## Metrics

| Metric | Meaning |
|---|---|
| `node_agent_state_writes_total{rule_id,result}` | Entries written |
| `node_agent_state_write_rejected_total{rule_id,reason}` | **Alert on this** — a rule is being starved of the state it needs |
| `node_agent_state_expired_total` | Reclaimed by TTL |
| `node_agent_state_purged_total` | Dropped by scope purge |
| `node_agent_state_entries{scope}` | Current entry count, published by each sweep. `scope` is the scope *kind* — `container`, `host`, `pod` or `node` — never a scope ID, which would be unbounded. The host bucket is reported apart from real containers because it is one of the two that TTL alone reclaims. Every kind is republished on each sweep, so a kind that drains reads as zero rather than keeping its last value. |

Counters are labelled by rule ID only, never by state key — a key is unbounded
cardinality.

## When a correlation rule does not fire

Every failure mode here is silent — the rule applies, loads, and simply never
matches. Work down this list in order; each step is cheap and rules out one cause.

**1. Is the clause even reaching the agent?** The `Rules` CRD must declare
`stateWrites`, or the API server prunes it. This is the most likely cause and the
hardest to guess, because `kubectl apply` reports success:

```bash
kubectl get rules <name> -n kubescape -o jsonpath='{.spec.rules[0].stateWrites}'
```

Empty output after a successful apply means the schema is missing the property.
`--validate=false` does not help — it skips client-side validation only.

**2. Did the clause fail validation?** node-agent logs
`RuleManager - invalid stateWrites clause` with the rule ID and the offending
write name. A rule that fails validation is degraded to non-correlating; the rest
of the CRD keeps evaluating.

**3. Is the rule bound?** Rules are inert until a `RuntimeRuleAlertBinding` lists
them by `ruleName`. A new rule ID does nothing on its own.

**4. Is the write leg reaching the rule loop?** Add a temporary control rule that
alerts on the *write* event type with the same predicate as your `when:` guard. If
the control is silent, the problem is upstream of the state store.

**5. Do the two legs agree on the join key?** Have the control rules print
`string(event.pid)` in their `message`, and compare. `has_ancestor` is the right
answer when the second leg is a *child* rather than the same process.

**6. Is the write being rejected?** `state_write_rejected_total` counts caps and
guard errors, labelled by rule ID.

**7. Could the events be reordered?** node-agent evaluates on a concurrent worker
pool, so two events milliseconds apart can be processed out of order. This is real
but usually not the cause — rule out everything above first.
