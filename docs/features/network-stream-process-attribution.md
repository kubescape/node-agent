# Network-stream process attribution

Every streamed connection carries the identity of the process that opened it, so
a malicious-endpoint finding can land on the same incident as the exec, file and
other findings from that same process chain. Before this, the network stream
carried no process data on the wire at all: the sensor captured a process tree
per connection and then stripped it before sending, to save bytes.

Schema lives in `armosec/armoapi-go` (pinned `v0.0.742`); this document covers
the **sensor** side, in `pkg/networkstream/v1`.

## What goes on the wire

```go
// per connection
NetworkStreamEvent.ProcessRef *ProcessRef   // "processRef" — NOT "process"

// per message
NetworkStream.Processes                 map[ProcessRef]*ProcessTree
NetworkStream.ProcessAttributionVersion int   // NetworkStreamProcessAttributionV1 = 1
```

`ProcessRef{PID, StartTimeNs}` text-marshals to `"<pid>/<startTimeNs>"` and is
deliberately both the per-event reference and the map key, so the join cannot
drift. Consumers must resolve it with `NetworkStream.ProcessTreeFor(event)`, never
a bare map index — indexing panics on a nil ref and cannot distinguish a missing
entry from a present-but-nil one.

`StartTimeNs` is **boot-relative nanoseconds**, taken from
`ProcessTreeManager.GetProcessBootTimeNs` and emitted **verbatim**. It is
converted from clock ticks exactly once, on the way in from `/proc` — see
[process-start-time.md](./process-start-time.md). Scaling it here would compile,
parse, and even join correctly *within* one message (the key and the ref share a
producer), while silently breaking identity across messages by seven orders of
magnitude. If you find yourself dividing this value, that is a bug.

A zero `StartTimeNs` is legal and means *unknown* — the process was not yet
`/proc`-scanned, died before its creation event was processed, or is a
Kubernetes-mode host process. The ref is emitted anyway: it degrades to pid-only
identity, where dropping it would lose attribution entirely for that population.
A pid of 0 is not an identity, and yields no ref at all.

## The batch key — this fixed data loss, not just attribution

Connections are batched per entity under a key from
`getNetworkEndpointIdentifier`. That key was `"<addr>/<port>/<proto>"` with
first-writer-wins, so when two processes in one container reached the same
endpoint inside a flush interval, the second connection was **silently
discarded** — it never reached the wire under any identity. The same held for two
processes resolving one domain, keyed on the DNS name alone.

The key now appends the ref:

| Case | Key |
|---|---|
| Attributed connection | `1.2.3.4/443/TCP/101/5000000000` |
| Unattributed (pid 0) | `1.2.3.4/443/TCP` |
| Attributed DNS query | `evil.example.com./101/5000000000` |

**Appended, never reordered.** An unattributed key stays byte-identical to the
pre-attribution format. For IP connections the two forms cannot collide: the
address, port and protocol components are structured, so an attributed key always
carries exactly two more of them. For DNS the name is unstructured, so an
unattributed query for a name that itself ends in `/<pid>/<startTimeNs>` would
collide with an attributed query for the name's prefix, and one of the two records
would be dropped. Contrived, and it costs one record rather than corrupting
attribution, but it is not impossible the way the IP case is.

First-writer-wins is retained for the *same* process, so a chatty process does not
inflate the batch.

Accepted consequence: an attributed and an unattributed connection to one
endpoint become two entries. The traffic-view write path collapses them to one
row — its row identity contains no process field — so this is not
customer-visible and needs no migration (verified, SUB-7851).

The ref is computed **before** `eventsStorageMutex` is taken. The lookup acquires
the process tree's read lock, and holding the storage mutex across it would add a
storage→tree lock-order edge for no benefit.

### Known cost: the ref lookup is on the packet path

`processRefFor` runs for **every** network and DNS event, including duplicates —
unavoidably, since the dedup key contains the ref, so the ref must exist before the key
can be built. It takes `ProcessTreeManagerImpl.mutex.RLock()` and then the creator's
`RLock()` to read one map entry, and `ProcessTreeManagerImpl.ReportEvent` write-locks
that same manager mutex for every exec/fork/exit/procfs event. Before attribution the
network path never touched those locks at all.

Measured on the duplicate-connection path (8 threads, real `ProcessTreeManagerImpl`;
control is the same benchmark with the lookup short-circuited):

| | ns/op |
|---|---|
| Idle tree, control | 210 |
| Idle tree, with ref lookup | 244 |
| 4 goroutines of exec churn, control | 254–271 |
| 4 goroutines of exec churn, with ref lookup | 996–1035 |

~16% idle, **~3.9× under exec churn** — essentially all write-lock contention, so it
lands hardest on the fork-heavy nodes this feature's budget was calibrated for. The
lookup is inherent to the design; the contention is not. A dedicated RWMutex for the
creator's `pidStartTimeNs` side map, or an atomic/sharded read, would keep packet
handling off the process-tree writer's critical path. That change belongs in
`pkg/processtree/creator` and is left to the workstream that owns it.

## The flush: one snapshot, two consumers

The flush has two consumers with different needs:

- **The in-process notification channel** — `private-node-agent`'s host network
  sensor reads `outbound.ProcessTree` from it. It keeps the trees. (In the
  open-source repo `cmd/main.go` passes a nil channel, which makes the field look
  dead. It is not.)
- **The HTTP exporter** — gets a derived wire copy where trees move into the
  message-level `Processes` map.

### Why the snapshot is independent

The flush used to hand the channel the **live** storage struct, then — still
holding `eventsStorageMutex` — sleep 100 ms and strip every process tree from the
maps the consumer was reading. The sleep was the only thing standing between the
host sensor and having its data erased mid-read. A test showed worse: a
connection recorded 300 ms *after* the flush appeared inside the
already-delivered snapshot, because the clear loop and the consumer shared the
same maps.

`snapshotNetworkStream` now allocates its own `Entities` map and its own
per-entity event maps, so the delivered value is immune to everything the
producer does next. Both sends happen outside the lock, and the 100 ms sleep is
**deleted rather than shortened** — there is no shared state left to race on.

The channel send stays blocking, so a slow consumer applies backpressure rather
than losing traffic, but it now selects on context cancellation as well. That was
impossible while the send held the lock; without it a stalled consumer would pin
the flush goroutine past shutdown.

### Lock discipline

This file has a history of mutex stalls on this path, so the bound is part of the
design rather than an afterthought:

| | Inside `eventsStorageMutex` | Outside |
|---|---|---|
| Work | Allocate the snapshot's maps; copy each event **by value**; clear the live storage | Both sends; the wire copy's tree deep-copies and command-line caps |
| Bound | O(entities + connections) small struct copies — at the largest observed message (109 entities, 283 connections) a few hundred copies | one capped tree copy per distinct process |

Process-tree **pointers** are copied into the snapshot, never walked. That is
what keeps the lock body cheap, and it is safe because a tree is immutable once
attached to an event: nothing mutates one in place. `buildBranchToShim` allocates
fresh nodes per branch, so event trees are not shared with the process tree's
live map — only with its 1-minute LRU entry, which nothing writes to after
construction. Anything that would modify a tree copies it first.

Transient memory outside the lock is one capped tree copy per *selected* process,
so it is bounded by `maxProcessTreeBytes` (2.5 MiB) rather than by the connection
count, and freed after the HTTP send. `capTreeCopy` runs only for candidates that
fit the budget.

The wire copy is derived **before** the snapshot goes on the channel. Once the
consumer has it, its maps are the consumer's; reading them afterwards would depend
on that consumer never writing to what it receives.

The table above covers the flush only. `eventsStorageMutex` is also held by
`handleNetworkEvent` across `buildNetworkEvent`, which calls `ResolveIPAddress`
and — on a cache miss — an unbounded `net.LookupAddr`. That is pre-existing and
untouched here (this change strictly reduces flush-side contention), but it is the
larger contributor to hold time on that mutex and should not be mistaken for
covered ground.

## The wire copy (`wire.go`)

`buildWireStream` derives the HTTP payload from the snapshot:

- Each event's tree moves into `Processes`, keyed by the event's own ref, and the
  per-event `ProcessTree` is cleared **on the copy only**.
- `ProcessAttributionVersion` is set **unconditionally**, including when nothing
  was attributable. `len(Processes) == 0` is not a capability signal — a sensor
  that ran and found nothing must stay distinguishable from one that predates
  attribution.
- `Processes` is left nil when empty, so `omitempty` drops it.
- A ref whose tree never resolved still ships. It dangles, and `ProcessTreeFor`
  is specified to return nil for that; dropping the ref would lose the pid too.

**One tree per process, not per connection.** Trees dominate the payload; the
duplicated ref bytes do not. The ref therefore travels twice per connection (map
key and event value) by design — do not "optimise" that away.

**On collision the deeper chain wins.** The process-tree cache TTL (1 minute) is
shorter than the flush interval (2 minutes), so two lookups for one process
inside a single interval can legitimately return chains with different amounts of
ancestry resolved. First-wins would discard the richer chain *and* would make the
payload depend on Go's randomised map iteration order.

### Why not `Process.DeepCopy`

`armotypes.Process.DeepCopy` **mutates its receiver**: it calls `MigrateToMap`,
which allocates `ChildrenMap` and nils `Children`, and it does so on every child
it recurses into — nodes the LRU cache, the alert paths and the channel consumer
are reading. `copyCappedProcess` is read-only instead, normalising the deprecated
`Children` slice into the copy's `ChildrenMap` without touching the source. Every
recursive walk here is bounded by `maxTreeDepth` (64), so a malformed or cyclic
tree costs a truncated payload rather than the agent's stack.

### The process-tree budget

Attribution changed **what sizes the payload**. Before, the batch key collapsed
every process reaching one endpoint into a single entry carrying no tree, so size
tracked *distinct endpoints*. Now the key splits per process and each distinct
process contributes a tree, so size tracks **distinct processes that connected
during the interval** — and nothing bounded that.

The original payload analysis (SUB-7850) modelled bytes per connection at a fixed
count of 283 connections. That is exactly the quantity the key change stops
holding fixed, so the multiplier on connection *count* was never budgeted.

Exceeding the limit is not a graceful degradation: `sendNetworkEvent` gets a
non-2xx, returns an error, `Start()` logs it and drops the snapshot. **The node
loses its entire interval of traffic** — no retry, no split. A node with heavy
short-lived process churn (a cron loop shelling out, a CI runner, exec-based
liveness probes) can reach that.

#### Calibration, from measured production traffic

| Input | Value | Source |
|---|---|---|
| Mean message on the topic | 29 KB (prod-us 32 KB) | `pulsar_average_msg_size` on `network-stream-v1` |
| Mean connections per batch | ~42 (prod-us ~32) | `network_reputation_events_in_total` ÷ topic message count |
| ⇒ bytes per connection, no tree | ~530 B of JSON | derived from the two above |
| Largest batch ever observed | 283 connections | SUB-7850 |
| Tree size | ~4.3 KB marshalled for a fully-populated 10-node chain | measured here (the plan documents give ~2 KB median and disagree on p90 — 5.1 KB vs the ~7 KB implied by its own ~2 MB ÷ 283) |

`maxProcessTreeBytes` is **2.5 MiB** of estimated tree bytes. Measured end to end
against the worst case it exists for — *every* connection from a distinct process,
so trees scale 1:1 with connections — with production-weight connection entries
(530 B) included:

| Connections (all distinct processes) | Trees shipped | JSON | after base64 |
|---|---|---|---|
| 42 (the mean) | all 42 | 0.20 MiB | 0.26 MiB |
| **283 (observed worst)** | **all 283** | 1.33 MiB | **1.77 MiB — 35% of limit** |
| 500 | 461 (budget binds) | 2.19 MiB | 2.92 MiB |
| 1000 | 461 | 2.49 MiB | 3.31 MiB |
| 4000 | 461 | 3.93 MiB | **5.24 MiB — over the limit** |

Tree bytes are measured; entry bytes are **modelled** at the production-derived 530 B,
not measured, so the two are added rather than read off one payload — see the residual
section for why that distinction matters.

This is why the 4000 row exceeding the limit does **not** contradict
`TestBuildWireStream_EscapeHeavyPayloadStaysUnderLimit` and
`TestBuildWireStream_OverBudgetDropsTreesNotConnections`, which drive comparable process
counts and assert the payload stays *under* 5 MiB. Those tests build synthetic events
carrying only a ref and a key — roughly 94 B each — where a production connection entry
is ~530 B. The tests bound what the code emits; the table adds the real-world entry
weight on top. Neither is a failing bound.

Two load-bearing rows. The **283** row: the budget must not bind on traffic
production actually produces, or it degrades attribution on exactly the busiest
nodes — a tighter 1.5 MiB was tried first and rejected, because it clips 70 of those
283 trees while the payload is barely a third of the limit.
`TestBuildWireStream_ObservedWorstCaseFitsBudget` pins that and fails at 1.5 MiB.
The **4000** row is the residual below: with the tree budget saturated, the message
exceeds the limit at roughly 3,600 connections.

- **A byte budget, not a tree count.** Tree size is not uniform — depth varies,
  fields are variable-length, and JSON escaping inflates some content ~6× (below),
  so no count bounds the payload. The estimator overestimates real marshalled size
  by ~33% for realistic trees, and `TestEstimateTreeBytes_NeverUnderestimates`
  enforces that it never goes the other way.

#### JSON escaping is what makes the estimate honest

`len(s)` is **not** what reaches the wire, and getting this wrong silently voided
the bound. `encoding/json` escapes `"` and `\`, every control byte, and — because
`Marshal` enables HTML escaping — `<`, `>` and `&`, which real command lines are
full of (`sh -c 'cmd > /dev/null 2>&1'`). Invalid UTF-8 is replaced byte-for-byte
with `�`, and process argv is arbitrary kernel bytes, not guaranteed UTF-8.
Each such byte costs up to **six** where `len()` counts one.

Charging `len()` therefore let a payload six times the estimate pass the budget: 629
processes with 1 KB of non-UTF-8 argv each estimated at 29% of the budget, dropped
nothing, logged nothing, and produced **5.37 MB after base64** — rejected by the
broker, so the node lost its entire interval of traffic. `escapedLen` charges the
true escaped cost (rounding every escape up to 6 bytes), which is what makes
`maxProcessTreeBytes` an actual bound. Note this is reachable deliberately by
anyone able to exec in any container on the node, which made it a detection-evasion
primitive rather than merely a bug.

Two further accounting gaps were closed after CodeRabbit review. A child's `comm` is
emitted **twice** — as its own field and inside the parent's `childrenMap` key, which
`CommPID.MarshalText` renders as `comm␟pid` — so it is now charged twice, together with
the key's structural bytes; and `containerID` was charged with a bare `len()`. Neither
was reachable in production: comm is only ever 15 bytes because every source is a kernel
`TASK_COMM_LEN` buffer, and container IDs are hex. But the estimate must not rest on an
invariant nothing in this repo enforces — with an unbounded comm the old accounting ran
**48% under**, and a bound that depends on an unenforced assumption is not a bound.
- **Connections are never dropped** — that is the data loss this change exists to
  fix. Only trees are, and the refs stay on the connections, so pid identity
  survives and `ProcessTreeFor` returns nil for them as specified.
- **Ranked smallest-tree-first**, ties broken on the ref. That maximises the number
  of processes keeping an attributable tree, which is the best objective available
  given the sensor cannot know which process will matter. Ranking by connection
  count was tried and rejected: a low-and-slow beacon opens exactly *one*
  connection per interval, so it would sort last and lose its tree first — the
  precise case reputation attribution exists to catch. The ref tie-break keeps the
  shipped set independent of map iteration order, which
  `TestSelectProcessTrees_IsDeterministic` pins.
- The budget holds ~461 fully-populated 10-node chains — 1.6x the observed worst
  batch — so it is a safety valve rather than a routine limiter.

**Residual, deliberately not fixed here.** Two things this budget does not cover.

First, **it bounds the wire, not the heap.** With the process-aware key,
`networkEventsStorage` retains one entry per (process, endpoint) for the whole flush
interval, each pinning a `*ProcessTree`, and nothing caps that — resident memory grows
with distinct processes even though the payload is trimmed on the way out. Capping it
would mean dropping connections, which is the data loss this change exists to fix, so
the honest position is that it is unbounded and monitored rather than bounded.

Second, connection volume alone can exceed the message limit. Be precise about which
number means what, because the difference decides what an operator should do:

| | connections |
|---|---|
| Breach **with the tree budget saturated** (today's configuration) | ~3,600 |
| Breach from connection **entries alone**, if trees took no space at all | ~7,400 |

The usable budget is 3.75 MiB of JSON (5 MiB after base64's x1.333). A saturated tree
map **measures** 1,978,505 B (1.89 MiB) — marshalled, not inferred — which leaves
3,932,160 - 1,978,505 = 1,953,655 B (1.86 MiB), so ~3,690 entries at 530 B. Independent
measurements put it at ~3,580 and ~3,600, hence **~3,600** above: rounding low is the
right direction for a breach threshold. Entries alone would not breach until
3,932,160 / 530 = ~7,400.

Derive this from the *measured* tree total, never from a payload figure that already
contains entries. Getting that wrong produced two successive errors here — a table row
that counted entries twice, and a ~3,000 threshold that survived the correction of the
tree figure it had been derived from.

**So the tree budget IS a lever in that regime** — trees are roughly half the payload,
and tightening `maxProcessTreeBytes` moves the breach point out, toward ~7,400 as the
budget approaches zero. That is the fastest thing to reach for during an incident: no
protocol change, no backend coordination.

Splitting the message remains the better long-term fix, because tightening the budget
buys headroom by shipping fewer process trees — the attribution this feature exists to
deliver — whereas splitting keeps all of it. One prerequisite before anyone builds it:
the container-profile precedent
(`docs/features/container-profile-split-on-413.md`) reacts to a **synchronous** HTTP 413
from storage's `QueueManager`. This path posts elsewhere, handles no 413 anywhere, and
the 5 MiB cap is a broker limit whose enforcement point is unverified (SUB-7850). If it
is enforced downstream at the broker, the sensor sees `200 OK` and never learns, so
reactive splitting is unavailable and the split must be decided before the first send.
Settle that before designing.

The logging below is what would tell us any of this is being approached.

### Observability, because the real distribution is not knowable yet

The calibration above bounds the worst case, but **how often a real node actually
has that many distinct processes cannot be measured from today's data**: the
current sensor strips trees and puts no process identity on the wire, so
distinct-processes-per-batch exists in no message. What is measurable — connections
per batch (~42 mean) and message size (~30 KB mean, ~175× under the limit) — bounds
the worst case only under the pessimistic assumption that *every* connection comes
from a different process. The real ratio of processes to connections is the unknown,
and it is bounded above by 1.

Two log lines make it answerable after rollout:

- `NetworkStream - process tree budget exceeded` — with `processesWithTrees`,
  `treesShipped`, `treesDropped`, `connectionsWithoutTree` and the byte totals.
  Fires once per flush, and only when the budget binds.
- `NetworkStream - large payload` — above `payloadWarnBytes` (2 MiB), with the
  marshalled size, entity, connection and tree counts. Reports the tail
  approaching the limit; quiet at the ~30 KB fleet mean.

If the first line turns out to fire routinely, the budget should become
configurable rather than being raised blind.

### Command-line cap

Each node's `Cmdline` is capped at **1024 bytes on the wire copy only**, with a
trailing `…` so a cut is visible to a human. `cmdline` is ~40% of a tree's bytes
and unbounded — a single pathological java or node command line can exceed
100 KB — so this is the lever that keeps the payload tail bounded, not an
optimisation. 1024 bytes keeps >99% of real command lines intact, and the cut
never splits a UTF-8 rune.

The cap is applied **during** the copy, so the legacy alert paths and the
notification-channel consumer keep the uncapped values.

## Handoff note for the host/ECS workstream

This change owns `pkg/networkstream/v1`; `cmd/host`, `cmd/ecs` and the
Kubernetes-mode streaming gate are untouched. Inheriting from it:

- The tree strip is gone, and with it the **shared-map race the host sensor's
  100 ms sleep existed to survive**. The channel now delivers an independent
  snapshot, still with trees.
- The batch key gained a process suffix (above).
- Outside Kubernetes mode the HTTP export is disabled entirely, so that
  in-process channel is the only consumer today.
- In Kubernetes mode, pre-existing **host** (non-container) processes carry no
  start time, because the tree refuses to create nodes for them.

## Testing

This package cannot be built or tested on macOS: `inspektor-gadget/pkg/utils/host`
excludes darwin and is imported transitively.

```bash
docker run --rm -v "$PWD":/src -v "$(go env GOMODCACHE)":/go/pkg/mod -w /src \
  -e GOFLAGS=-mod=mod golang:1.25 go test ./pkg/networkstream/...
```

`pkg/networkstream/v1` had two test functions before this change, so it carries
its own coverage rather than leaning on a surrounding suite.
