# Process start time

Every process in the process tree can carry a creation time. It exists to tell
apart two processes that share a process id — the kernel recycles ids, and
without a creation time a recycled id looks like the process that held it before.

There are **two representations, and they are not interchangeable**:

| Value | Where | Unit | Use for |
|---|---|---|---|
| `ProcessTreeManager.GetProcessBootTimeNs(pid)` | Creator side map | Nanoseconds since boot (`CLOCK_BOOTTIME`) | **Process identity.** The only value that may be compared. |
| `armotypes.Process.StartTime` | Tree node, and every alert's process tree | Wall-clock `time.Time` | **Display only.** Never compare it. |

## Why two

The identity value must be exact. The display value is derived through
`/proc/stat`'s `btime`, which has **whole-second resolution**, so it carries up
to a second of skew. Two processes created 40 ms apart can share a wall-clock
start time while their boot-relative values differ correctly.

So: show `Process.StartTime` to a human, compare `GetProcessBootTimeNs` in code.
Anyone comparing the wall-clock value for identity is wrong by up to the btime
skew, and will be wrong intermittently rather than consistently.

## Where the value comes from

`/proc/<pid>/stat` field 22 (`starttime`), the process's creation time in clock
ticks since boot. It is converted **once**, on the way in:

```text
boot-relative nanoseconds = ticks × 10,000,000        (USER_HZ = 100)
```

Nothing downstream rescales it. A division at emission would compile, parse and
even join correctly *within* a single message, while silently breaking identity
across messages by seven orders of magnitude. If you find yourself scaling this
value on output, that is a bug.

**The unit implies more precision than the value carries.** USER_HZ is 100, so
every value is an exact multiple of 10 ms. Do not treat it as a timestamp.

### `(pid, startTimeNs)` is not guaranteed unique

The 10 ms quantization means two processes created within the same tick share a
start time. For a **join key** built from `(pid, startTimeNs)` — which is what
the network-stream attribution work uses — that leaves a residual collision: a
process id recycled and reused inside the same 10 ms window produces two
incarnations with an identical tuple, and they are indistinguishable.

This is narrow but real, and it is a limitation of the source rather than of
this code — `/proc` does not expose anything finer. Treat the tuple as a strong
discriminator, not a unique identifier, and do not build logic that assumes
two matching tuples must be the same process.

**It is never derived from an event timestamp.** `convertExecEvent`,
`convertForkEvent` and `convertExitEvent` set `ProcessEvent.StartTimeNs` from the
event's wall-clock timestamp — epoch nanoseconds, a different clock domain, and
stamping the event instant rather than process creation. That value feeds
pending-exit sort ordering only and must never reach the identity map. An exec
event in particular stamps the exec, so a re-exec would change it.

## When it gets populated

Two paths, both reading the same kernel source:

- **The periodic `/proc` scan** (every 30 s) — covers processes that predate the
  agent, so coverage completes within one interval of startup.
- **On demand, when a fork or exec creates a tree node** — without this, every
  process shorter than one scan interval would carry zero, and short-lived
  processes are both the bulk of beacon-style connections and the drivers of
  process-id churn.

The on-demand read happens **once per node creation, never per event**. An exec
on a node that already has a value does not re-read: creation time cannot change
on exec.

### Cost, and why the fork read is taken outside the tree lock

A single `/proc/<pid>/stat` open-read-parse measures **~7.5 µs** (Go benchmark,
Linux container, warm). Fork is the highest-volume event path on a node —
thousands per second on a busy one — and **every fork performs a read**, because
the recycled-pid guard below drops any stale value before the read decision is
made.

At 1,000 forks/s that is ~7.5 ms of read time per second; at 3,000/s, ~22 ms/s.
Taken while holding `pt.mutex`, the tree-wide write lock, that would be hold
time blocking every reader of the process tree — and the tree is shared by every
alert type, not just the consumer this field was added for.

So the fork path reads **before** acquiring the lock and stores the result under
it. Same number of reads, none of them holding the lock; fork contributes zero
added lock hold time. `TestHandleForkEvent_ReadsStartTimeWithoutHoldingTreeLock`
pins this, using `TryRLock` so a regression fails rather than deadlocks.

Exec keeps its read inside the lock, where the skip-when-already-known check
makes it conditional and it only fires on first sight of a pid.

The tradeoff: reading before the lock widens the window between the event and
the read. If the pid is recycled inside that window the value belongs to the new
incarnation — the same already-accepted race as before, just slightly wider, and
the reuse hardening is what detects it.

### Zero means unknown

A read fails if the process is already gone. The value stays zero rather than
being guessed. Callers must treat `0` as "unknown", never as "created at boot".

Two populations keep a zero start time, both accepted:

- Processes that died before their creation event was processed (sub-second
  queue latency).
- In Kubernetes mode, pre-existing **host** (non-container) processes — the tree
  refuses to create nodes for them at all.

### Recycled process ids

A fork's process id is newborn, so a surviving identity entry can only belong to
a process the kernel already recycled that id away from. The fork handler drops
the stale entry before reading, so the new process gets its own creation time.

This matters because exits linger: `exitCleanup.cleanupDelay` defaults to five
minutes, so a dead process's tree node and its identity entry outlive it by that
long.

The wipe is gated on the pid actually having a **pending exit**. An existing node
alone does not prove reuse — some other path may simply have created it first —
and wiping on that weaker signal would discard a good scan-recorded value
whenever the on-demand read then fails.

> **This guard covers the identity map only**, and on its own it was not
> process-id-reuse hardening.
>
> By itself it left the dead process's `pendingExits` entry in place, so the
> delayed cleanup would later run `exitByPid` on that pid and delete what was by
> then the **live** successor's node, along with the start time just read for it.
> During the same window the node also still carried the dead process's `comm`,
> `cmdline` and `path`, so an alert could name the wrong command.
>
> Both are now fixed: a fork or exec on a pid with a pending exit retires the
> predecessor properly — reparenting its children rather than merely dropping the
> pending entry, which would leave them to be inherited by the successor. See
> [process-id-reuse-hardening.md](./process-id-reuse-hardening.md), which also
> covers the two recycle cases this guard never saw: one discovered only by the
> `/proc` scan, and a delayed exit arriving for a node that is provably newer.
>
> The guard here still earns its place. It is what keeps the identity and display
> halves of the start time from disagreeing, and it remains the fallback when the
> teardown cannot complete because reparenting failed.

The entry is deleted at the same point the tree node is deleted.

## Reading it

```go
// Identity — the only value safe to compare.
ns := processTreeManager.GetProcessBootTimeNs(pid)
if ns == 0 {
    // Unknown: not yet scanned, died before its creation event, or a host
    // process in Kubernetes mode. Fall back to process-id-only handling.
}

// Display — carried on every node of every alert's process tree.
node.StartTime // wall clock, up to 1s of skew, never compare
```

`Process.StartTime` reaches consumers only because three separate copy functions
were taught to carry it. Each builds a node from an **explicit field list** and
silently drops anything absent from it:

- `containerprocesstree.buildBranchToShim` — every alert branch and every
  network-stream tree
- `utils.CopyProcess` — the alert bulk manager's merged tree
- `utils.EnrichProcess` — the bulk manager's merge of overlapping chains

Each has a dedicated test asserting the field survives. **If you add a field to
`armotypes.Process` and expect it downstream, you must update all three** —
otherwise it is populated at the source and silently empty at the consumer.

One builder deliberately still strips it: `utils.CreateProcessTree`
(`pkg/utils/process.go`), used by the malware manager, so malware alerts carry a
zero start time. Tracked separately.

## A note on the wire

`armotypes.Process.StartTime` is a `time.Time` tagged `omitempty`, and Go's
encoder ignores `omitempty` on structs. The field has therefore always been
serialised — as `"startTime":"0001-01-01T00:00:00Z"` — so populating it changes
an existing value rather than adding a new one. Nothing branches on it and there
is no hash or equality over `Process`, but consumers do see the change.

## Testing

This package cannot be built or tested on macOS: `inspektor-gadget/pkg/utils/host`
excludes darwin and everything under `pkg/processtree` imports it transitively.

```bash
docker run --rm -v "$PWD":/src -v "$(go env GOMODCACHE)":/go/pkg/mod -w /src \
  -e GOFLAGS=-mod=mod golang:1.25 go test ./pkg/processtree/... ./pkg/utils/...
```

The tick conversion is defined once per package (feeder and creator). Both are
pinned in tests against an independently read field 22 times a literal `10^7`,
so if the two ever drift, a test fails deterministically. Weaker forms of that
check are not enough: `ns % 10^7 == 0` only catches a 10× error when
`ticks % 10 != 0`, and comparing the wall-clock value against "now" loses
sensitivity on a freshly booted machine.
