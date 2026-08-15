# Process-id reuse hardening

The kernel recycles process ids. The process tree keeps an exited process's node
for up to `exitCleanup::cleanupDelay` after it dies, so for that window a pid can
be held by a **live** process while the tree still holds the **dead** one's node
under the same pid. Nothing in the tree used to notice.

Two things went wrong as a result, and both were confirmed by reproduction rather
than inferred:

1. **The new process reported the dead one's identity.** `handleForkEvent` fills
   only *empty* fields, and a stale node is not empty, so a recycled pid kept the
   predecessor's `Comm`, `Cmdline`, `Path`, `Cwd`, `Uid` and `Gid`. **A runtime
   alert of any type could name the wrong command.**
2. **The dead process's delayed exit deleted the live process's node.**
   `exitByPid` matches on pid alone, so when cleanup finally fired it removed
   whatever node held that pid by then — reparenting a running process's children
   around it and taking its start time with it.

Neither self-corrects for the cases that matter: an alert emitted inside the
window has already been exported with the wrong command, and the node deletion
leaves children reparented around a process that is alive. What *does* self-correct
is the *field* staleness on a pid that goes on to exec or be rescanned, which is
why the likelihood of the first is rated medium rather than high.

See [process-start-time.md](./process-start-time.md) for the identity value this
work builds on, and
[process-tree-exit-manager-lifecycle.md](./process-tree-exit-manager-lifecycle.md)
for the deferred-deletion model that opens the window.

## Three layers

Each is independent, and each falls through to today's behaviour when its input is
unknown. None of them may ever *keep* a node it cannot prove is newer: retaining
stale state is the harmful direction, re-deleting a node is not.

| Layer | Signal | Needs a clock? |
|---|---|---|
| A fork or exec retires a pending-exit predecessor | The event itself | No |
| A delayed exit skips a node newer than the exit's arrival | `CLOCK_BOOTTIME` comparison | Yes |
| The procfs scan rebuilds a node whose start time changed | Start-time inequality | No |

### 1. A fork or exec retires the predecessor

A fork or exec for a pid **proves a new live incarnation holds it** — a zombie can
do neither. So a pending exit on that pid must belong to a dead predecessor, and
`retireRecycledPredecessor` tears that predecessor down before the handler touches
the node. No clock is involved, which is why this layer is independent of the
start-time work entirely.

The guard runs **before** the node lookup, not only where a stale node was found.
A pending exit can outlive its node — the exit may arrive for a pid the tree never
created a node for, or another path may already have removed it — and the recycled
fork then builds a fresh node that the stale entry would delete at the next
cleanup. `TestPidReuse_ForkAfterExit_ConsumesPendingExitWithNoNode` fails if the
guard is gated on an existing node.

> **The proof is a kernel-ordering argument, and the pipeline does not preserve
> kernel order.** Fork, exec and exit come from three separate tracers, each with
> its own goroutine, feeding one queue that is drained in batches and sorted only
> within a batch. An exit enqueued after its batch drained is processed after a
> fork that really preceded it, and this layer reads that as a recycle: it retires
> a node that was about to be legitimately deleted, and consumes a real pending
> exit.
>
> The result is a dead node left in the tree, not a live one deleted, and it
> self-heals — `sendExitEvents` re-synthesises an exit for any tree pid absent from
> `/proc` every `ProcfsPidScanInterval` (5 s), so the window is bounded wherever
> that reaper runs. Tightening it needs no new clock: the fork/exec event timestamp
> and `pendingExit.StartTimeNs` are both wall-clock event stamps, so declining to
> retire when the fork/exec is the *earlier* of the two is a same-domain
> comparison. Not done here, deliberately — it trades a bounded, self-healing
> staleness for a new ordering dependency.

#### Retiring means the full teardown, not dropping the pending entry

This is the part that looks safe to simplify and is not.

```go
// WRONG — passes the obvious tests, corrupts the tree more quietly
delete(pt.pendingExits, pid)
```

That does stop the delayed deletion, and it does let the new process's fields be
written. But the dead process's **children are still linked to the pid**, so the
new process silently inherits them. The tree then claims an unrelated live process
is the parent of another process's children, and every alert built from that
branch carries the lie. It is harder to notice than the bug it replaces.

`retireRecycledPredecessor` therefore performs the full teardown, which reparents
the children away first. `TestPidReuse_ForkAfterExit_DoesNotInheritDeadChildren`
fails if this is ever simplified back — it asserts both that the recycled pid has
no children and that the orphan survives, reparented, rather than being deleted
with its parent.

### 2. A delayed exit never deletes a provably-newer node

For a recycle discovered *without* a fork or exec — the scan found the new process
first — the guard is purely temporal: a node whose recorded creation time is
**later than the moment the exit event arrived** cannot be the process that exit
was for.

Both sides are boot-relative nanoseconds. The side map holds `/proc` starttime
ticks × 10⁷; the arrival is stamped with `CLOCK_BOOTTIME` when the pending exit is
recorded. **No wall clock is involved on either side, and none may be introduced**
— `pendingExit.Timestamp` and `pendingExit.StartTimeNs` are wall-clock values with
unrelated jobs (cleanup ageing and sort ordering respectively), and comparing
either against the side map would be meaningless rather than merely imprecise.
`pendingExit.StartTimeNs` in particular is **not a process start time** at all; it
is the exit event's timestamp.

Two populations are deliberately **not** covered:

- **Nodes with no recorded start time.** There is nothing to compare, so the guard
  falls through to today's deletion rather than guessing. Layer 1 covers these
  whenever the recycle is seen via fork or exec, needing no clock.
- **Reordered events.** If the exit arrives *after* the recycled process was
  already scanned, the arrival is the later value and the guard deletes — today's
  behaviour — and the next procfs scan recreates the node. That recovery runs
  through the **node-absent** path, not layer 3: the teardown deletes the side-map
  entry along with the node, so the prior start time layer 3 compares against is
  gone and its check declines.

> **A newer recorded start time does not prove the node's *contents* were
> rebuilt.** Layer 3 only fires when the side map already held a non-zero value, so
> when the predecessor had none — a fork-created node whose on-demand read failed,
> or a node auto-created as a parent — the scan **merges** the successor's fields
> into the dead node, keeping its `ChildrenMap`, and writes the successor's start
> time. Layer 2 then sees a value newer than the arrival and keeps that merged
> node, so the successor inherits the predecessor's children: the same shape as the
> trap below, reached by a different route.
>
> It self-corrects within one full scan interval (30 s) when each child's own procfs
> event fixes its PPID — except where `UpdatePPID`'s Kubernetes container-subtree
> branch declines the update. Closing it properly means letting layer 3 fire on a
> zero prior value, which cannot distinguish "recycled" from "first ever reading"
> and would tear down healthy nodes on first sight. Left open knowingly.

`TestPidReuse_DelayedExit_NormalExitStillDeletes` pins the mirror case: an
ordinary, non-recycled exit must still remove its own node. Without it, writing
the comparison the wrong way round would leak every exited process's node forever
and no other test would notice.

### 3. The procfs scan rebuilds a recycled node

Two procfs readings of the same process yield the *identical* starttime ticks, so a
different non-zero value is proof of recycling — exact inequality, no tolerance,
and none should be added.

On detection the stale node is torn down and rebuilt from the event. Merging is
never correct here: the handler's overwrite-only-if-non-empty logic preserves any
field the new process does not report, so the dead process's `Cwd` would survive
into a node otherwise describing the new one.

The rebuild re-applies the Kubernetes host-process policy that the first-sighting
path enforces. Without that, a host procfs event could materialise a node the same
event would be refused on first sight.

**The teardown reparents every child, and not all of them necessarily belonged to
the dead process.** This layer can fire up to a scan interval after the recycle, by
which time the successor may already have forked, so a live child can be detached
and reparented to init. Versus today that is a trade rather than a pure win —
today's behaviour retains dead children instead — and it self-corrects on the
child's next scan. Layer 1 does not have this problem, because it fires on the
first fork or exec, before the successor has children.

`TestPidReuse_ProcfsSameStartTime_MergesAsToday` is the control — an equal start
time means the same process, so the refresh must keep today's merge semantics and
keep the node's children.

#### Why a pending exit is not the signal on this path

`handleProcfsEvent` must **never** treat a pending exit as recycle proof. `/proc`
lists zombies, so a procfs event can legitimately belong to the same incarnation
that already exited — the pending exit would be correct, not stale, and tearing
the node down would be wrong.

The same asymmetry applies to "the node already exists", which is a much weaker
signal than it looks: another path may simply have created the node first. Every
guard here is gated on a **pending exit** or on a **changed start time**, never on
mere existence — an earlier version of the start-time guard wiped a correct value
on that weaker basis.

## The gap no layer covers: a fork processed before the exit it follows

The two reorder cases described above are per-layer. There is a third, symmetric to
the first, that **all three layers decline** — so both original bugs survive it.

Kernel order is `P1 exits` → pid recycled → `P2 forks`, but the **fork event is
processed before the exit event**:

| Layer | Why it declines |
|---|---|
| 1 | There is no pending exit yet when the fork is handled, so there is nothing to retire. |
| start-time fallback | The `else if … exited` branch in `handleForkEvent` is gated on the same pending exit. |
| 2 | The fork's on-demand read has already recorded P2's real creation time, which **precedes** the late exit's arrival, so `startNs > ArrivalBootNs` is false. |
| 3 | The side map now holds P2's start, so the next procfs reading matches it and no rebuild triggers. |

Confirmed against the implementation: after the fork the node still reports P1's
`Comm` and `Cmdline`, and the late exit then deletes P2's live node.

Severity is low and this is deliberately **not** fixed. The reorder window is about
one drain batch of the event queue, and a pid recycling inside it is essentially
impossible — the 32,768-entry pid space would have to wrap in milliseconds. Closing
it would mean making the guards depend on event ordering they cannot verify, which
trades a near-impossible case for a new class of ordering bug.

It is recorded here because the other two reorder blind spots are, and because
finding it later without this note would read as a regression rather than a known
edge.

## The shared teardown

`removeProcessNode` holds the teardown — reparent children, unlink from parent,
delete the node and its identity entry — so the exit path and the procfs rebuild
cannot drift apart. It is deliberately independent of `pendingExits`, because the
rebuild needs the same teardown for a pid that has no pending exit at all.

It returns `false` when the node could not be removed, which today means
reparenting failed. Both callers then leave their own bookkeeping untouched, so
the operation degrades to today's retry-on-the-next-tick behaviour rather than
inventing a partial teardown. In that state the fork handler still falls back to
the narrower start-time guard, and the node keeps its stale fields — today's
behaviour, reached deliberately.

## Cost

Under `pt.mutex`, the additions are a `pendingExits` map lookup on the fork and exec
paths and one integer comparison on the procfs path. The teardown only runs in the
recycle case. **No `/proc` read is added.**

**The one syscall this work introduces is taken outside the lock.** Layer 2 needs
`CLOCK_BOOTTIME` at the moment an exit is recorded, and `unix.ClockGettime` is a
raw syscall — `x/sys` does not route it through the vDSO the way the runtime does
for `time.Now`. Exits are about as frequent as forks, so `handleExitEvent` reads the
clock **before** acquiring `pt.mutex` and passes the value into `addPendingExit`,
exactly as the fork path does with its start-time read. Anything that moves that
read back under the lock is a regression.

That pattern is the thing to preserve. A start-time read costs **~7.5 µs** and every
fork already performs one, which is why it happens outside `pt.mutex` — at 3,000
forks/s it would otherwise add ~22 ms/s of hold time to a lock every alert type
depends on, and this package has a prior mutex-stall fix in its history. Read the
cost section of [process-start-time.md](./process-start-time.md) before adding work
here.

## Observable changes

The first three are recycle-scenario only:

- A fork or exec on a pid with a pending exit reparents the dead process's
  children **immediately** rather than after the cleanup delay.
- A delayed exit no longer deletes a node whose recorded creation postdates the
  exit's arrival.
- A procfs start-time change rebuilds the node instead of merging two
  incarnations. Because the rebuild reparents every child, a child the successor
  forked before the scan noticed it is detached to init — see layer 3 above.
- `forceCleanupOldest` no longer makes a second, redundant pass over the same
  pending exits. That pass was silent while a repeat call always found the node
  already gone; now that a guard can legitimately keep a node and consume its
  pending entry, the second pass would log a warning for every node kept.

Same-incarnation behaviour is unchanged. This matters more than usual because
`GetContainerProcessTree` serves the rule manager and every exporter, so this code
path sits behind **every** alert type, not just the consumer the start time was
added for.

## Testing

macOS cannot build this package: `inspektor-gadget/pkg/utils/host` excludes darwin
and everything under `pkg/processtree` imports it transitively. All runs in the
Linux container:

```bash
docker run --rm -v "$PWD":/src -v "$(go env GOMODCACHE)":/go/pkg/mod -w /src \
  -e GOFLAGS=-mod=mod golang:1.25 go test -race ./pkg/processtree/...
```

Every reproduction and guard test lives in
`pkg/processtree/creator/pid_reuse_test.go`. Note that the pull-request pipeline
does not run the race detector — `CGO_ENABLED: 0` is hardcoded in
`.github/workflows/pr-created.yaml`, gating the race step off (SUB-7848) — so race
evidence for changes here has to come from the command above.
