# Container Profile Split on HTTP 413

An HTTP 413 ("Request Entity Too Large") from storage's `QueueManager` signals that a single delta—one transaction body—exceeded the wire's byte capacity. This is a **transport** rejection, not a lifecycle signal. Prior behavior mapped a 413 onto `ObjectTooLargeError` (storage's authoritative "aggregate too large" sentinel), which ended learning for the entire container, discarding all future deltas forever.

A single oversized delta does not mean the container's *aggregate* profile is full. Storage merges deltas server-side, dedupes findings, and only emits a true `ObjectTooLargeError` when the aggregate's findings count exceeds its limit—a separate check entirely. This change splits an oversized delta into two independently-named halves, re-enqueues both, and lets learning continue. The transport limit is no longer conflated with the aggregate limit, and containers survive an occasional large delta.

## Why a 413 is not "too large"

Storage operates at two levels:

| Signal | Source | Meaning | Response |
|---|---|---|---|
| HTTP 413 `Content-Length` check | `QueueManager.Create()` (kubescape/storage pkg/queuemanager/manager.go:144-148) | This **one delta** exceeds the wire cap (default ~2.5 MB) | Node-agent: halve and retry; do not end learning |
| `ObjectTooLargeError` sentinel | Storage's aggregate findings-count check (kubescape/storage pkg/registry/file/containerprofile_processor.go) | The container's **cumulative profile** (after merge and dedup) exceeds findings cap (e.g. 100K) | Node-agent: end learning authoritatively (`OnQueueError` → `deleteContainer`) |
| `ObjectCompletedError` sentinel | Storage's completion check | Container has finished reporting (age, findings completed) | Node-agent: end learning authoritatively |

Today, a 413 is incorrectly treated as a terminal `ObjectTooLargeError`, so one large delta ends the entire container. The fix: only the **sentinels** end learning. A bare 413 triggers reactive halving instead.

## Reactive halving

When a delta is rejected with 413, `splitProfile()` (pkg/containerprofilemanager/v1/queue/containerprofile_split.go) partitions its data into two profiles with:

- **Same base aggregate name** — both halves carry the same `ObjectMeta.Name` prefix, differing only in the one-time UUID suffix. Storage's own `SplitProfileName` function recovers the base by cutting on the last hyphen, so both halves aggregate into the same server-side profile.
- **Per-field partition** — `Capabilities`, `Execs`, `Opens`, `Syscalls`, `Endpoints`, `IdentifiedCallStacks`, `Ingress`, `Egress`, and `PolicyByRuleId` are split across the two halves by element. Each field's `a` half takes `ceil(len/2)` elements, `b` takes the rest. Per-field splitting (rather than random bin-packing) guarantees that whichever field dominates the byte size is itself halved on the first round, which bounds convergence.
- **Verbatim baseline** — `Architectures`, `ImageID`, `ImageTag`, `SeccompProfile`, `LabelSelector`, and all annotations/labels are **copied identically** into both halves. This non-split baseline (`K`) is replicated, so a depth-*d* leaf is `K + P/2^d`, where `P` is the partitionable payload.

### Convergence

Assuming the baseline `K` is smaller than storage's cap (the usual case):

```
K + P/2^d < cap   =>   d = ceil(log2(P / (cap - K)))
```

With a default `MaxSplitDepth = 4`, this covers roughly a **16x overshoot** of the cap. Each round takes one `RetryInterval` (default 5 seconds), so a 3.23 MB chunk against a 2.5 MB cap converges in ~1 round of wall-clock time.

If `K >= cap` (e.g. the `SeccompProfile` alone exceeds storage's limit), splitting cannot converge at any depth. The byte-progress guard detects when neither half is meaningfully smaller than the parent (`max(size(a), size(b)) >= size(p)`) and stops splitting at that point, treating it as a floor case (see below). This is a node-agent estimator bug, not a storage limitation, and surfaces as a Warning drop counter so the issue can be escalated.

Both halves **retry at the queue's natural tick rate** (no busy-loop). The `queueSize` captured at the start of `processAllItems` (pkg/containerprofilemanager/v1/queue/containerprofile_queue.go) ensures splits land on the **next** tick, so split storms are naturally rate-limited by the queue's existing backpressure.

### Non-convergent floor case

If a delta has **≤ 1 partitionable element** (e.g. one huge `Endpoint` that is the entire profile), it cannot be split usefully. The chunk is dropped and replaced with a **stitch chunk**—a metadata-only stand-in that preserves the report-timestamp chain (see §3 below) but clears the payloads that could not be split. The stitch is a couple of KB and cannot itself be rejected with 413.

Dropping the chunk (rather than ending learning) is a deliberate degradation trade-off: one delta is lost, but the container keeps learning and eventually completes. The drop counter signals that node-agent's size estimator (mixing byte-size and element-count heuristics) is overshooting; this is tracked as a separate node-agent bug.

## Naming and aggregation

The original chunk has an `ObjectMeta.Name` in the form `<base>-<uuid>`, where `<uuid>` is a 32-hex one-time slug generated by `InstanceID.GetOneTimeSlug`. When the chunk splits, both halves get **fresh UUIDs** via `freshOneTimeSlug()` (pkg/containerprofilemanager/v1/queue/containerprofile_split.go):

```
parent:  myapp-production-abc123def456...
a:       myapp-production-xyz789uvw012...  (fresh UUID)
b:       myapp-production-ghi345jkl678...  (fresh UUID)
```

Storage's aggregation key is per-object—it parses the name with `SplitProfileName`, recovering the base (`myapp-production`) and treating each UUID as a distinct `time_series` row within that aggregate. Both halves' rows merge into the same aggregate, so the data is unified server-side.

The one-time slug cannot use a scheme like `-part1`/`-part2` because `SplitProfileName` cuts on the **last** hyphen—a hyphenated suffix would be mistaken for the UUID, scattering data into phantom aggregates.

## The report chain (timestamp interposition)

This is the most delicate part of the design. Storage's `consolidateContinuousTimeSeries` function (kubescape/storage pkg/registry/file/containerprofile_processor.go:631-659) walks a container's time-series rows in reverse chronological order, merging each row `j` with row `i+1` **only when** `timeSeries[j].PreviousReportTimestamp == timeSeries[i+1].ReportTimestamp`. This linear-chain walk reconstructs the container's lifecycle—every row must link back to the prior report.

If two halves share the parent's timestamp pair `(P, T]` (where `P` is previous and `T` is report), they form a broken fork:

```
rows (ORDER BY reportTimestamp DESC) = [a(P,T), b(P,T)]
merge:  a.prev(P) == b.rt(T)?   NO  → chain breaks, len(newTimeSeries) = 2
```

The `updateProfileStatus` function (kubescape/storage pkg/registry/file/containerprofile_processor.go:672) then sees two rows instead of one and sets `Learning` status, preventing completion forever—the profile is stuck in learning limbo despite all data being present. This was a real, verified defect in design review: **any container that ever splits stays in `Learning` forever and never completes**.

The fix: interpose a fresh timestamp `X` strictly between `P` and `T`, via `chainHalves()` (pkg/containerprofilemanager/v1/queue/containerprofile_split.go), giving `a` the interval `(P, X]` and `b` the interval `(X, T]`:

```
rows = [b(X,T), a(P,X)]
merge: b.prev(X) == a.rt(X)?   YES  → merges to [(P,T)]
```

Storage's consolidation collapses the two rows back to the original interval, so the **next** real report—whose `previousReportTimestamp` points at `T`—still links up. The chain is linear and unbroken.

### Timestamp preservation and parsing

Only `X` is manufactured. The two halves preserve the parent's endpoints byte-for-byte:

- `a.previousReportTimestamp` = parent's original string (unchanged)
- `b.reportTimestamp` = parent's original string (unchanged)
- `a.reportTimestamp` = `b.previousReportTimestamp` = `X.String()` (manufactured)

Timestamps come from `time.Now().String()` (see pkg/containerprofilemanager/v1/monitoring.go:184-185), which emits the Go time layout `"2006-01-02 15:04:05.999999999 -0700 MST"` **plus** a monotonic-clock suffix like `" m=+0.000019007"`. The `time.Parse` function cannot parse that suffix; it fails with `extra text: " m=+0.000019007"`.

The `parseReportTimestamp()` function (pkg/containerprofilemanager/v1/queue/containerprofile_split.go) handles this by:

1. Stripping the monotonic suffix: `s, _, _ = strings.Cut(s, " m=")`
2. Attempting to parse with the primary layout `"2006-01-02 15:04:05.999999999 -0700 MST"`
3. Falling back to a numeric-zone layout `"2006-01-02 15:04:05.999999999 -0700 -0700"` for non-whole-hour timezones (Nepal `+0545`, Iran `+0330`, etc.)

Both layouts are required: Go's zone-letter abbreviations (`MST`, `CEST`) fail to parse for non-whole-hour offsets, but numeric offsets like `+0545` do parse. This was a blocking defect in design review: without stripping the monotonic suffix, **every production `chainHalves` call would fail to parse and refuse to split**, silently dropping chunks instead of recovering them.

### Zero-time first-report hazard

On a container's first report, `previousReportTimestamp` is the zero time. A true midpoint between year 1 and now lands around year 1013. Storage's `ListTimeSeriesExpired` function (kubescape/storage pkg/registry/file/sqlite.go:349-356) compares `reportTimestamp` as a **raw string**, so a year-1013 timestamp matches the expiry check unconditionally and the profile is marked `Completed`/`Partial`—re-ending learning on the most common split case (a large delta on a container's initial burst of learning).

The solution: `interposeTimestamp()` (pkg/containerprofilemanager/v1/queue/containerprofile_split.go) never takes a midpoint. Instead:

```
if prev is zero time:
    X = rt.Add(-1ms)              // step back by delta
else:
    X = rt.Add(-min(delta, (rt-prev)/2))
if !(prev < X < T):
    return false                  // refuse to split
```

This keeps `X` far from `prev` when `prev` is ancient, and ensures the `P < X < T` invariant holds.

### Stitch chunks (metadata-only repairs)

When a chunk is dropped (floor case, depth exhaustion, etc.), a **stitch chunk** via `stitchChunk()` (pkg/containerprofilemanager/v1/queue/containerprofile_split.go) is enqueued in its place. A stitch carries:

- The same `previousReportTimestamp` and `reportTimestamp` strings (byte-for-byte, so the chain link is preserved)
- The same annotations and labels
- A fresh one-time UUID (a new `Name`)
- A `Spec` with payloads cleared: `Capabilities`, `Execs`, `Opens`, `Syscalls`, `Endpoints`, `IdentifiedCallStacks`, `Ingress`, `Egress`, and `PolicyByRuleId` are empty, but `SeccompProfile`, `ImageID`, and `ImageTag` are **preserved verbatim**

Why preserve only three fields? Storage's `mergeContainerProfileTS` (kubescape/storage pkg/registry/file/containerprofile_processor.go:855-881) merges most fields by **append**, but these three by **unconditional assignment** (lines 863, 865, 866)—the last merge wins. Rows merge in DESC order, so the oldest row wins. Clearing `SeccompProfile`/`ImageID`/`ImageTag` would zero them on the aggregate.

A stitch is a couple of KB and cannot exceed the 413 cap. If it is rejected with 413 (which should never happen), it is dropped without re-stitching via the `IsStitch` flag (pkg/containerprofilemanager/v1/queue/containerprofile_queue.go), to avoid an infinite loop. This gap (one half of a pair lost) forks the chain, leaving the profile stuck in `Learning`—a known limitation tracked as a follow-up against the queue's LRU eviction and `MaxAttempts` retry exhaustion.

### Temporary shim

This entire timestamp-interposition mechanism is a **temporary shim**. Once storage's `consolidateContinuousTimeSeries` is updated to collapse rows sharing an identical `(previousReportTimestamp, reportTimestamp)` pair within a series (tracked as kubescape/storage follow-up), this code can be removed and splits can leave both timestamps untouched, eliminating the parsing and zero-time hazards entirely.

## Bounds and queue integration

### MaxSplitDepth

`MaxSplitDepth` defaults to 4 (pkg/containerprofilemanager/v1/queue/containerprofile_split.go `DefaultMaxSplitDepth`), bounding a single lineage at `2^4 = 16` leaves. This tripwire catches:

- **Pathological input** — a chunk 16x over the cap (indicating a node-agent size-estimator bug)
- **LRU eviction worst case** — the queue's `MaxQueueSize` evicts FIFO from the head while splits append to the tail. Capping one lineage at 16 leaves (net queue growth +15 per lineage) ensures split storms don't silently evict unrelated healthy profiles.

Each halving round takes one `RetryInterval` (default 5 seconds), so depth 4 represents a maximum ~20-second wall-clock convergence time under pathological input.

### Inheritance and attempts

When a chunk is split, both halves (pkg/containerprofilemanager/v1/queue/containerprofile_queue.go `requeueSplit`):

- Inherit the parent's `Attempts` counter (not reset to 0), so the retry budget is a real bound
- Get `SplitDepth = parent.SplitDepth + 1`
- Retain `IsStitch = false` (so they can split further if needed)

Inheriting `Attempts` keeps the budget honest: a payload alternating between retryable failures and 413s cannot refresh its budget indefinitely by splitting.

## Observability

Two counters track split behavior (pkg/containerprofilemanager/v1/queue/containerprofile_queue.go `GetQueueStats`):

| Counter | Method | Meaning |
|---|---|---|
| Splits | `ReportContainerProfileSplit()` (metricsmanager.MetricsManager) | Chunks successfully halved after 413. Increasing rate suggests node-agent's size estimator is firing; review byte-cap and element-count heuristics (separate node-agent issue). One-round convergence is normal; sustained deep convergence suggests estimator drift. |
| Drops | `ReportContainerProfileChunkDropped(reason)` | Chunks discarded because they could not be split further. Rising drop count on production clusters warrants investigation. |

Drop reasons are typed constants (pkg/containerprofilemanager/v1/queue/containerprofile_queue.go):

| Reason | Meaning |
|---|---|
| `dropReasonUnsplittable` | Floor case (≤1 partitionable element), unconstructable chain timestamp, or no byte progress (`max(size(a), size(b)) >= size(p)`) |
| `dropReasonDepthExhausted` | `MaxSplitDepth` reached before convergence |
| `dropReasonStitchRejected` | A stitch chunk was itself rejected with 413. The chain fork is left open (known limitation). |
| `dropReasonEnqueueFailed` | The stitch replacement could not be enqueued (rare; the queue is full or degraded). |

## Tests

- `pkg/containerprofilemanager/v1/queue/containerprofile_split_test.go` — comprehensive unit tests of the split algorithm:
  - Chain linearity (`TestChainHalves_ConsolidatesToParentInterval`, `TestSplitProfile_RecursiveChainStaysLinear`) — ensures the timestamp interposition is correct and consolidation (via a golden port of storage's own algorithm) reconstructs the original interval, including under recursive re-splitting
  - Zero-time and boundary cases (`TestChainHalves_ZeroPreviousTimestamp`, `TestParseReportTimestamp_MonotonicSuffix`, `TestParseReportTimestamp_NumericZoneAbbreviation`)
  - Non-convergence (`TestSplitProfile_NoProgressGuard`) and floor-case drops (`TestSplitProfile_FloorCase`)
  - Determinism (`TestSplitProfile_Deterministic`)
  - Stitching (`TestStitchChunk_PreservesAssignmentMergedScalars`)

- `pkg/containerprofilemanager/v1/queue/containerprofile_queue_errors_test.go` — queue-level integration:
  - Split dispatch and requeue (`TestQueueSplitsProfileOnHTTP413`, `TestQueueDropsUnsplittableProfileOnHTTP413`)
  - Depth bounds (`TestQueueRespectsMaxSplitDepth`)
  - Stitch-rejection loop prevention (`TestQueueDoesNotStitchAStitch`)
  - Persistence across a queue restart (`TestQueuePersistsSplitDepth`)

- End-to-end: no new e2e tests are added (the split is internal; no new public API). Existing learning-completion tests should pass without change (profiles should complete normally even when internal chunks split).

## Known limitations

1. **Node-agent estimator.** The `MaxTsProfileSize` threshold mixes byte-size and element-count heuristics. This PR tolerates occasional 413s via splitting, but the root cause (the estimator) is tracked separately and remains a node-agent bug.

2. **LRU eviction and MaxAttempts gaps.** If exactly one half of a split pair is evicted from the queue (by LRU due to `MaxQueueSize`) or exhausts `MaxAttempts` retries before landing, the chain fork persists and the profile hangs in `Learning`. This gap is pre-existing (the same failure mode applies today via the pre-existing `MaxAttempts` drop path and is not new). A comprehensive fix requires explicit half-tracking across queue evictions, tracked as a follow-up against the queue's LRU and retry-budget design.

3. **No "too-large ends learning" signal on transport rejection.** Prior to this change, a 413 ended learning loudly with an `ObjectTooLargeError` status. Now, a 413 silently splits (or is silently dropped if unsplittable). Storage's own sentinels (`ObjectTooLargeError`, `ObjectCompletedError`) still end learning authoritatively and will log. But if a container is stuck splitting/dropping chunks forever with no terminal status ever reached, that silent degradation may require the drop counters and debug logs to diagnose. This trade-off (silently degrade one delta vs. silently end the container) is intentional.
