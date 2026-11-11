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
    value:                              # optional extras, CEL expressions that yield a string
      exe: "event.exePath"
    ttl: 10m                            # clamped to the configured maxTtl
expressions:
  ruleExpression:
    - eventType: network                # alerts on a DIFFERENT stream
      expression: |
        state.has("mount_exec", string(event.pid)) && !net.is_private_ip(event.dstIP)
```

`name` is a literal rather than an expression on purpose: it stays statically
analysable and is safe to use as a metric label.

Each `value:` entry must evaluate to a **string**. A list or a number (such as
`event.args`) fails evaluation and that field is silently omitted, with only a
debug log; the entry is still stored without it. Convert explicitly:
`"event.args.join(' ')"`, `"string(event.ppid)"`.

### Writes are declarative, not a CEL setter

There is no `state.set(...)` function, deliberately. A setter inside a predicate
would be skipped by boolean short-circuiting, could be reordered by the static
optimiser, and could never express "remember this **without** alerting" — which
is exactly what the first leg of a cross-event rule needs.

### Three operations: set, increment, clear

A `stateWrites` entry performs exactly one of three operations. `increment` and
`clear` are opt-in fields; an entry with neither is a **set**, with or without a
`value:` map, which is what every marker write above is.

| Operation | Field | Meaning |
|---|---|---|
| set | neither; `value:` optional | remember a fact; last write wins, TTL refreshed |
| increment | `increment: 1` | create the entry with count 1, or add 1; the window is fixed from creation |
| clear | `clear: true` | delete the entry if present |

All three share `eventType`, `when`, `scope`, `name` and `key`. `ttl` is
required on `set` and `increment`; on `clear` it is optional and ignored, so an
entry can be copied and its operation flipped. `increment` accepts only `1`.
An explicit `increment: 0` or `clear: false` is rejected, not read as absent:
an author who wrote either meant something, and a silent set that never counts
is the failure validation exists to prevent. Validation also rejects any other
`increment` value, more than one of `value` / `increment` / `clear` on one
entry, and a name declared as both a set and an increment within one rule.

A counter is how a rule expresses a threshold: "the tenth outbound SSH
connection from one process within a minute".

```yaml
id: R1213
stateWrites:
  - eventType: network
    when: "event.dstPort == uint(22) && !net.is_private_ip(event.dstIP)"
    scope: container
    name: ssh_out
    key: "string(event.pid)"
    increment: 1
    ttl: 1m
  - eventType: network                 # reset the window after alerting
    when: 'state.count("ssh_out", string(event.pid)) >= 10'
    scope: container
    name: ssh_out
    key: "string(event.pid)"
    clear: true
expressions:
  ruleExpression:
    - eventType: network
      expression: 'state.count("ssh_out", string(event.pid)) >= 10'
  message: "'outbound SSH burst: ' + string(state.count(\"ssh_out\", string(event.pid))) + ' connections in a minute from ' + event.comm"
```

### Ordering: increments before the expression, set and clear after

For one event, the rule loop runs in three steps:

1. every `increment` write for this event whose `when:` passes;
2. the rule expression, which alerts if it holds;
3. every `set` and `clear` write whose `when:` passes.

So a **set** is only ever visible to **later** events — otherwise a rule that
reads and writes the same name on the same event type would satisfy itself from
its own write. An **increment**, by contrast, is counted before the expression,
so **the count includes the current event**: on the tenth qualifying event
`state.count()` reads 10, and `>= 10` means the tenth event, not the eleventh.
The self-satisfaction argument does not apply to a counter: the author declared
the increment on this very event type, so counting it is the intent.

Consequences:

- A `clear` guarded on the threshold runs *after* the alert, so the event that
  alerts also resets the window. Without a `clear`, the rule alerts on every
  event from the Nth on, limited only by cooldown.
- A `when:` on an increment is evaluated before the expression, against the same
  context. It may read `state.count()` of the entry it is about to increment and
  sees the value *before* the increment. Reads made inside an increment's guard
  are not cited as the alert's evidence; evidence is what the expression read.
- The count an event reads is the count **its own increment produced**.
  node-agent evaluates events concurrently, so a fresh store read could see a
  later event's increment; instead the value each increment returned is held for
  the rest of that event's evaluation and served to `state.count`, `state.has`,
  `state.get` and the evidence. Exactly one event observes each value, so
  `== N` fires exactly once per crossing.
- A `clear` is a plain delete and may race: in a burst, an event that
  incremented to N+1 before the Nth event's `clear` landed still reads N+1 and
  also alerts, and the clear may discard that increment. `>= N` with a `clear`
  can therefore produce a small number of extra alerts in a burst (deduplicated
  by `uniqueId` and cooldown); `== N` is the exact form.

### Near-simultaneous events can miss each other

node-agent evaluates events on a concurrent worker pool, and a write only
becomes visible once the event that made it has been fully evaluated. Two
events a few milliseconds apart are therefore not guaranteed to be processed in
order: the second leg of a chain can be checked *before* the first leg's marker
lands, and the rule does not fire.

This is measured, not theoretical. On a loaded node, `base64 -d | sh` (both
processes start in the same instant) correlated in 8 of 20 runs, "exec then
connect out" keyed on the pid in 25 of 30 when thirty processes started at once
and worse under file-write load, while the same chains with a one-second gap
between the legs correlated every time. Scripted attacks run their steps exactly
this fast, so:

- Prefer a key the **later** leg can resolve on its own — `has_ancestor` against
  a marker written on the *parent* survives the child starting before the
  parent's write is visible more often than a same-pid key does.
- Where the two legs are the same process, consider whether a single-event rule
  on the second leg with a `when:`-free marker and a cooldown is good enough.
- Expect the gap to be closed by the engine (ordering same-process-tree events
  on one worker, or a brief re-check on a miss), not by rule authoring; both are
  tracked as follow-ups to NAUT-1348.

Plain counters are not affected: an increment is atomic in the store, and the
value each event reads is the one its own increment produced, so bursts count
exactly. The guarded distinct-count recipe below **is** affected, for the same
reason — its guard read and marker write are two operations.

### Window semantics

A counter's TTL is **fixed from the first increment** and is not refreshed by
later ones. It is measured on the agent's clock from the moment the increment
was applied, not from the event's own timestamp: under ingestion lag an event
can be older than its ttl, and a window anchored to it would be born expired.
`_ts` still records when the first event happened. When the entry expires, the next increment creates a fresh one with
count 1 and a new window. So "ten in a minute" means ten since the window opened,
and a burst that straddles a window boundary can read as two sub-threshold halves;
the fixed window undercounts at a boundary by at most a factor of two. Rolling
windows are not supported.

Provenance on a counter (`_ts`, `_pid`, ...) describes the **first** event of
the window. A `set` to a name that holds a counter replaces it, count and all,
and resets the TTL as any set does; validation rejects a name declared with both
`value`/set and `increment` in the same rule. `clear` may be combined with either.

### What suppresses a write

| Condition | Writes still run? |
|---|---|
| Rule disabled, or does not apply to this context | no |
| `profileDependency: Required` and no profile | no |
| Pre-filter excluded the event | no — counted as `state_write_rejected_total{reason="prefiltered"}` |
| Rule policy suppressed it | no — counted as `reason="policy"` |
| **Alert cooldown** | **yes** |
| **Predicate returned false** | **yes** |
| Store at capacity | no — write rejected, `state_write_rejected_total` |

Cooldown suppresses the *alert*, never the write: writes are evidence gathering,
and dropping them would break the next leg of the chain.

**The pre-filter case is the one to watch when writing a correlation rule.** A
rule's pre-filter is built from the rule as a whole — in practice mostly from its
alerting leg's parameters — but it is applied to every event type the rule
touches. So a rule whose `network` leg carries `ignorePrefixes` or
`excludeProcesses` has those same parameters applied to its `exec` leg, and the
write is dropped. The chain then never forms, and nothing about the resulting
silence points at the pre-filter. That is why the two suppression paths are
counted: a non-zero `reason="prefiltered"` for a rule that is not firing is the
answer. Where the parameters are genuinely meant for one leg only, the fix is to
express them in that leg's `expression` instead of as rule-level pre-filter
parameters.

### DNS writes follow the rule-facing event type

The DNS tracer emits a single `dns` stream, but the rule loop selects
expressions by the rule-facing type: an answered response is `dns`, while a
forwarded query or an error response is `dnsQuery` (see
`dns-query-rule-forwarding.md`). A write uses the same renaming, so
`eventType: dnsQuery` on a write is driven by exactly the events a `dnsQuery`
expression sees, and `eventType: dns` on a write never fires on a bare query. The
entry's `_eventType` provenance carries the rule-facing name too, so a remembered
query and a remembered answer are distinguishable. Both names are accepted by
validation; `dnsQuery` requires armoapi-go v0.0.771 or later.

### Validation

An unknown event type, `eventType: all` (a binding wildcard, not a stream),
`scope: identity` (operator-only), a bad or non-positive TTL, or a `_`-prefixed
name or value key is rejected. Every one of those mistakes would otherwise produce
a rule that loads cleanly and silently never fires.

Validation runs on the rule's first matching event rather than at load, because a
rule reaches the loop by two paths and only one of them populates load-time
derived fields. The compiled result is then cached, keyed by a fingerprint of the
clause, so an edited rule recompiles on its own without an invalidation hook.

The practical consequence is that a malformed clause is reported the first time
the rule sees a matching event, not at apply time — and reported **once per
version of the clause**, not once per event. A TTL above `maxTtl` is clamped and
logged on the same terms.

A rule with a malformed clause is degraded to non-correlating and logged; it does
not stop the other rules in the CRD from evaluating.

The clause's CEL expressions — `when:`, `key:` and each `value:` entry — are a
separate case, because they are compiled lazily on first evaluation rather than
by the validator. A compile failure is logged once and cached, and **every later
evaluation of that expression keeps failing**, on every event. What a failure
costs depends on the expression: a failing `when:` or `key:` skips the write and
is counted under `guard_error` or `key_error`, while a failing `value:` entry is
logged and that one field is omitted from the entry, which is still stored. A
failure never degrades into an empty guard or an empty key. The distinction matters for
`key:` in particular — an empty key names the scope-wide entry, so a key that
silently evaluated to `""` would turn a per-process marker into a container-wide
one. The same rule applies to `message` and `uniqueId`: a `uniqueId` that does
not compile drops the alert on every event, rather than shipping it under one
constant ID.

### Bounds

Over-capacity writes are **rejected, never satisfied by evicting** a live
entry — eviction would let one container disable detection for its neighbours.
Expired entries are another matter: a write that hits the per-scope cap first
drops that bucket's expired entries and retries, so a rule whose window has
ended does not keep holding the container's slots until the next periodic sweep.
The walk is bounded by the cap and touches only the one full bucket.

The per-scope cap is **shared by every rule** writing into that container. One
rule that stores many entries (a per-path marker recipe, say) can exhaust the
bucket and every other state rule in the container is then silently unable to
create entries — its `state.count()` reads 0 and its markers never land — for as
long as those entries are live. That is also an evasion path: fill the bucket
with cheap noise first, then act. Size `maxEntriesPerContainer` for the sum of
the rules you deploy, watch `state_write_rejected_total{reason="scope_cap"}`,
and prefer narrow keys. Per-rule caps are tracked as a follow-up to NAUT-1348.

The per-scope cap is exact; the node-wide ceiling is approximate under
concurrency. At the ceiling a write first tries to reclaim expired entries, but at
most one such sweep runs per `sweepInterval` across all writers — otherwise every
write at a full store would walk all 16 shards under their locks, stalling the
whole rule loop at the busiest possible moment. A write arriving between sweeps is
treated as though the sweep freed nothing, which is what it would have found. Host processes share one `c:__host__` bucket with its own larger cap,
since it holds the whole node's process space and gets no removal purge; node scope
takes that same larger cap for the same reason. A host process is recognised by
either spelling of its container ID — the production `host` pseudo-container ID
(`armotypes.HostContainerID`) or an empty ID — and both land in that one bucket;
the mapping is made in a single place, so reads, writes, purge and the
`node_agent_state_entries{scope="host"}` gauge cannot disagree about it.

## Reading state

Five functions, on a `state` receiver:

```cel
state.has(name)                  // bool  — for a fact about the whole scope
state.has(name, key)             // bool  — for a fact about one subject
state.get(name)                  // map   — empty map on a miss, never an error
state.get(name, key)             // map
state.count(name)                // int   — a counter's value, 0 on a miss
state.count(name, key)           // int
state.has_ancestor(name)         // bool  — any ancestor PID carries the marker
state.get_ancestor(name)         // map   — the NEAREST matching ancestor
```

`state.count` returns 0 on a miss or on a plain marker, never an error, so a
threshold predicate is simply false until the counter exists. `state.has` and
`state.get` work on counter entries as on any other, and `has_ancestor` /
`get_ancestor` see them too.

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
| `_count` | int | The counter's value. Present only on entries written by `increment`. |

`_pid` and `_ppid` are unsigned, while `event.pid` is not, so
`state.get(...)._pid == event.pid` mixes numeric types. It is safe — cel-go
compares numbers across types by value, and a test pins that in the production
evaluator — so the comparison neither errors nor silently returns false. The join
itself should still go through `key: string(event.pid)`: it is the cheaper lookup
and does not depend on that behaviour holding.

### Counting distinct subjects

"More than fifty distinct files opened by one process" is a set size, not a
counter. It composes from a marker write and a guarded increment, with no new
engine support:

```yaml
stateWrites:
  - eventType: open                       # one marker per distinct path
    scope: container
    name: seen_path
    key: "string(event.pid) + ':' + event.path"
    ttl: 5m
  - eventType: open                       # count it only the first time
    when: '!state.has("seen_path", string(event.pid) + ":" + event.path)'
    scope: container
    name: distinct_paths
    key: "string(event.pid)"
    increment: 1
    ttl: 5m
```

Because increments run before set writes, on the first open of a path the guard
sees no marker, the counter increments, and then the marker is written. On the
second open the marker exists and the increment is skipped.

**This recipe is approximate, not exact.** Treat its count as a lower-cost
estimate and set thresholds with margin, because three things can move it:

- **Concurrent repeats overcount.** The guard read and the marker write are not
  one atomic operation. Repeats of the same subject that are evaluated at the
  same time all see "no marker yet" and each increments. In testing, one process
  opening the same file 100 times in a tight loop counted as 12 distinct files,
  and 50 files written three times each read as high as 150; a rule that counts
  "token commands from two or more cloud CLIs" produced false "two providers"
  alerts from ten parallel calls to one CLI. This is the distortion most likely
  to produce a false positive.
- **The next window undercounts.** The marker's TTL is refreshed on every
  rewrite, but the counter's window is fixed. A process that keeps rewriting
  the same files outlives its counter window, and when the counter restarts the
  markers still exist, so those files are never counted again. A slow, steady
  rewriter can stay under threshold indefinitely.
- **The cap distorts rather than stalls.** Each distinct value costs one entry
  against the per-container cap of 256, shared by every subject in the container
  and by every rule. At a threshold of N the recipe counts correctly for about
  `256 / (N + 1)` subjects at once (two processes at N = 100, eight at N = 30).
  Past that, new markers are rejected (`scope_cap`) but the counter, which
  already exists, keeps incrementing on every guard miss — so the count can
  *inflate* once the container is full rather than stall.

An atomic add-if-absent write, or a native distinct set, would make this exact;
both are tracked as follow-ups to NAUT-1348.

### The ancestor functions assume a PID key

`has_ancestor` / `get_ancestor` probe each ancestor PID in turn, so they only
find entries whose `key` was a PID. That is an authoring contract, not something
the engine can check — write `key: string(event.pid)` for any name you intend to
read this way.

They work identically for host and containerised processes.

**Keying on `ppid` is a trap.** A shell runs the *last* command of `sh -c '…'`
in place, without forking, so that command's parent is the shell's parent, not
the shell. Every `kubectl exec` session in a container shares that grandparent.
A marker keyed on `string(event.ppid)` therefore both misses a real "A then B"
sequence inside one `sh -c` and matches unrelated sessions. Write the marker on
the event whose process *is* the shell, keyed on its own pid, and read it with
`state.has(name, string(event.pid)) || state.has_ancestor(name)`.

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
remembered `process`, and any author `values`. A counter entry carries its
count in `values` under `_count`, as of the read. Only hits are recorded — a miss is
not evidence of anything — and the record is reset before **every** rule, whether
or not that rule declares state, so one rule never cites another's entries. A
stateless rule evaluated after a correlating one on the same event alerts with no
`correlations` at all.

**Correlation enriches an incident; it does not re-key it.** `InfectedPID` and
`RuntimeProcessDetails` continue to describe the *triggering* event, so backend
incident grouping is unchanged. An alert with no correlations serializes exactly
as before, with no `correlations` key.

### Which exporters carry it

Only the **HTTP exporter**. That is a property of the payload shapes, not an
oversight, and it is not expected to change:

| Exporter | Carries `correlations[]`? |
|---|---|
| HTTP | yes — the only nested-JSON payload |
| Alertmanager | no — labels are a flat `map[string]string` |
| stdout | no — a fixed set of structured log fields |
| CSV | no — a fixed column set |
| syslog | no — a flat message |

Every exporter other than HTTP emits a flat, fixed-shape record, so carrying a
nested array would mean changing that exporter's schema rather than adding a
field. A rule that correlates still alerts normally on all of them; only the
evidence of the far leg is absent. If you are asserting on correlation evidence —
in a test or a downstream consumer — the HTTP exporter is the one to read.

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
| `node_agent_state_writes_total{rule_id,result}` | Entries written: `ok` for a set or an increment, `cleared` for a clear that removed an entry |
| `node_agent_state_write_rejected_total{rule_id,reason}` | **Alert on this** — a rule is being starved of the state it needs. `scope_cap` / `global_cap` are the store's own limits; `prefiltered` and `policy` mean a suppression meant for the rule's *alerting* leg silenced its *write* leg instead (see below); `guard_error`, `key_error` and `scope_unresolved` are the clause failing to evaluate |
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
`--validate=false` does not help — it skips client-side validation only. The
same applies per field: a chart whose CRD predates `increment` and `clear`
prunes those two fields and the entry degrades to a plain set that never counts,
so `state.count()` stays 0. Check `jsonpath='{.spec.rules[0].stateWrites[0].increment}'`.

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
pool, so two events milliseconds apart can be processed out of order and the
second leg checked before the first leg's write is visible. If the chain fires
reliably when you put a one-second `sleep` between the legs and not without it,
this is the cause; see "Near-simultaneous events can miss each other" above.
