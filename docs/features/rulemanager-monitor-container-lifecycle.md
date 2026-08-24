# RuleManager per-container monitor goroutine lifecycle

`RuleManager.monitorContainer` (`pkg/rulemanager/containercallbacks.go`) is the
goroutine `ContainerCallback` spawns (via `startRuleManager`) for every
`EventTypeAddContainer` notification. It used to have no scoped way to know
when *its own* container registration ended.

## The bug

The old exit condition polled shared mutable state on a 5s ticker instead of
listening for its own registration's removal:

```go
case <-syscallTicker.C:
    if !rm.trackedContainers.Contains(k8sContainerID) {
        return nil
    }
```

`ContainerCallback` dedups `EventTypeAddContainer` by checking
`trackedContainers.Contains(k8sContainerID)` and spawns a new
`monitorContainer` goroutine whenever that check is false — including right
after a `EventTypeRemoveContainer` for the same ID clears it. If a container
is removed and re-added faster than the 5s ticker, the sequence is:

1. Add(A) → tracked, goroutine **G1** spawned.
2. Remove(A) → untracked.
3. Add(A) again, before G1's next tick → tracked again, a **second**
   goroutine **G2** spawned for the same ID.
4. G1's ticker fires and finds `trackedContainers.Contains("A") == true`
   (re-added at step 3) — indistinguishable from "still my container" — so it
   loops forever instead of exiting.

Every such remove→add cycle inside one tick period leaked one goroutine
permanently (only full process shutdown, via `rm.ctx.Done()`, ever collected
them).

## The fix

Each `ContainerCallback` `EventTypeAddContainer` now creates its own
`chan struct{}` ("done") and stores it in a new
`RuleManager.trackedContainerDone` map keyed by `k8sContainerID`, alongside
`trackedContainers`. That channel is passed directly into `startRuleManager`
→ `monitorContainer` as a parameter, not looked up by ID:

```go
select {
case <-rm.ctx.Done():
    return nil
case <-done:
    return nil
}
```

`EventTypeRemoveContainer` closes and deletes the current registration's
channel. Because `monitorContainer` holds its `done` channel via closure
rather than re-reading a shared map/set by ID at wake time, only the removal
that closes *that specific channel object* can stop it — a sibling
registration's channel (or a later re-Add's fresh channel) has no effect on
it. This closes the race structurally instead of narrowing the polling
window.

One side effect: `monitorContainer` no longer polls on a timer at all, so the
now-unused `syscallPeriod` ticker and its `container.Mntns == 0` debug check
were removed along with it.

## Observable changes

- A container remove→add cycle no longer leaks a `monitorContainer`
  goroutine, regardless of how fast the cycle repeats.
- `monitorContainer` exits immediately when its container is removed, instead
  of up to `syscallPeriod` (5s) later.

## Testing

`pkg/rulemanager/containercallbacks_test.go` pins:

- `TestMonitorContainer_ExitsOnDoneChannel` — exits when its own channel
  closes.
- `TestMonitorContainer_IgnoresSiblingDoneChannel` — does **not** exit when
  an unrelated channel closes.
- `TestContainerCallback_FastRemoveAddDoesNotLeakGoroutine` — reproduces the
  Add→Remove→Add race end-to-end through `ContainerCallback` and asserts the
  first registration's channel is closed (so its goroutine can exit) while
  the second (current) registration's channel stays open and distinct from
  the first.

Run with the race detector:

```bash
go test -race ./pkg/rulemanager/... -run 'TestMonitorContainer|TestContainerCallback'
```
