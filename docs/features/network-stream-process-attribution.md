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
pre-attribution format, and an attributed key always carries two more components,
so the two can never collide. First-writer-wins is retained for the *same*
process, so a chatty process does not inflate the batch.

Accepted consequence: an attributed and an unattributed connection to one
endpoint become two entries. The traffic-view write path collapses them to one
row — its row identity contains no process field — so this is not
customer-visible and needs no migration (verified, SUB-7851).

The ref is computed **before** `eventsStorageMutex` is taken. The lookup acquires
the process tree's read lock, and holding the storage mutex across it would add a
storage→tree lock-order edge for no benefit.

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

Transient memory outside the lock is one capped tree copy per distinct process —
at most connections × p90 tree size ≈ 283 × 5.1 KB ≈ 1.4 MB worst case, freed
after the HTTP send.

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
