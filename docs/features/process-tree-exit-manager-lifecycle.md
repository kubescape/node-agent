# Process-tree exit manager — lifecycle and concurrency contract

The exit manager is the background half of `pkg/processtree/creator`. A process's
exit does **not** remove its tree node immediately: `handleExitEvent` only records
a pending exit, and a ticker goroutine removes the node later, once the exit has
aged past `exitCleanup::cleanupDelay`. The delay exists so a node is still
present when an alert refers to a process that has just died.

| Setting | Default | Role |
|---|---|---|
| `exitCleanup::cleanupInterval` | `30s` | How often the loop looks for due exits |
| `exitCleanup::cleanupDelay` | `5m` | How long an exit waits before its node is removed |
| `exitCleanup::maxPendingExits` | `1000` | Cap; reaching it force-drains the oldest pending exits immediately |

Because of the cap, the window in which an exited process's node is still in the
tree is **min(cleanupDelay, time-to-cap)** — on a busy node it is far shorter than
five minutes.

## Starting and stopping

`Start()` arms the manager; `Stop()` shuts it down. The state is carried by one
field, `exitCleanupStopChan`:

- **non-nil** — the manager is armed.
- **nil** — the manager is stopped, and `Start()` may bring it back up. The
  manager is restartable, and `Stop()` on an already-stopped manager is a no-op.

The field is an **intent** flag, not a liveness flag, and the difference matters
when reading or testing this code. It is non-nil before the goroutine has been
scheduled, and nil while a signalled loop is still finishing its current
iteration. Nothing should read it as "the loop is running".

Two rules make that safe, and both matter:

**Closing the channel is the stop signal. Clearing the field is only the
"not running" flag.** These are separate jobs that happen to use one field.

**The loop never reads the field.** `exitCleanupLoop` takes the channel as an
argument, so it holds its own reference for its whole lifetime and is unaffected
by a concurrent `Stop()` clearing the field. This is not a stylistic choice —
reading the field from the loop's `select` on every iteration, while `Stop()` wrote
to it, was a data race (SUB-7847). It accounted for every race the detector
reported in `pkg/processtree`, and it had two further consequences:

- Two concurrent `Stop()` calls could both observe an open channel and both close
  it: `panic: close of closed channel`.
- A loop that read the *cleared* field rather than the *closed* channel blocked
  forever on a nil-channel receive. That killed the stop arm of its `select`, so
  the loop kept ticking — and kept mutating the tree — for the lifetime of the
  process.

Both lifecycle transitions are therefore held under `exitCleanupMutex`, which
makes the check-and-close one atomic step.

### Why a dedicated mutex and not the tree lock

`performExitCleanup` holds `pt.mutex`, the tree-wide write lock, for its whole
pass. Guarding the lifecycle with that same lock would make shutdown wait on
tree contention, and the tree is shared by every alert type. `exitCleanupMutex`
guards only the two transitions and is never held while doing tree work, so the
two locks are never held together and cannot order against each other.

### `Stop()` is not instantaneous

Closing the channel does not preempt an in-flight iteration, and when both arms
of the loop's `select` are ready the Go runtime picks between them **at random**.
So a cleanup pass — occasionally more than one — can still run after `Stop()`
returns. The guarantee is that the loop terminates promptly, not that it performs
zero further work.

Tests that assert "nothing was cleaned up after `Stop()`" must let the loop
observe the close before seeding whatever they measure; asserting on the very
next tick is flaky by construction. `TestExitManager_StopHaltsCleanupLoop` pins
the real contract — cleanup does not continue indefinitely — and documents this.

## What removal does, and one thing it does not check

Removing a node reparents its children, unlinks it from its parent, deletes the
node, and deletes the pid's entry in the process-identity side map. See
[process-start-time.md](./process-start-time.md) for that side map.

> `exitByPid` no longer matches on **pid alone**. A fork or exec retires a
> recycled predecessor before the delayed cleanup can reach it, and the cleanup
> itself skips a node whose recorded boot-relative creation time postdates the
> exit's arrival.
>
> The window is narrowed, not closed: a node with no recorded creation time has
> nothing to compare, so it still falls through to unconditional deletion. See
> [process-id-reuse-hardening.md](./process-id-reuse-hardening.md) for the layers
> and for what each deliberately does not cover.

## Testing

This package cannot be built or tested on macOS:
`inspektor-gadget/pkg/utils/host` excludes darwin and everything under
`pkg/processtree` imports it transitively. Concurrency changes here need the race
detector, which the pull-request workflow does not currently run
(`CGO_ENABLED: 0` is hardcoded, gating the race step off — SUB-7848), so run it
locally:

```bash
docker run --rm -v "$PWD":/src -v "$(go env GOMODCACHE)":/go/pkg/mod -w /src \
  -e GOFLAGS=-mod=mod golang:1.25 go test -race ./pkg/processtree/...
```
