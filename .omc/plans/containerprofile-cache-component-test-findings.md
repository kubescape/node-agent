# Component Test Failures on PR #788 — Root Cause Analysis

**Scope**: `https://github.com/kubescape/node-agent/pull/788` — 13 of 24 component tests FAILED on CI run 24773018102. This is a real, blocking bug introduced by the migration. Merging without fixing this will regress production alerting.

**Verdict**: ❌ **REAL BUG — do not merge as-is.**

---

## 1. Symptom

13 tests fail, all with the same signature:

```
alertmanager.go:126: expected alert with rule name: Unexpected process launched  command: ls  container name: server  not found
alertmanager.go:127: All alerts: []
alertmanager.go:126: expected alert with rule name: DNS Anomalies in container   command: curl container name: nginx   not found
alertmanager.go:127: All alerts: []
```

"All alerts: `[]`". **Zero alerts** were fired for the anomalous execs that the test expected to flag. The legacy caches flagged these correctly; the new cache does not.

Failing tests (all alert-dependent):
Test_01_BasicAlertTest, Test_02_AllAlertsFromMaliciousApp, Test_12_MergingProfilesTest, Test_13_MergingNetworkNeighborhoodTest, Test_14_RulePoliciesTest, Test_16_ApNotStuckOnRestart, Test_17_ApCompletedToPartialUpdateTest, Test_19_AlertOnPartialProfileTest, Test_20_AlertOnPartialThenLearnProcessTest, Test_21_AlertOnPartialThenLearnNetworkTest, Test_22_AlertOnPartialNetworkProfileTest, Test_23_RuleCooldownTest, Test_24_ProcessTreeDepthTest.

Passing tests are the ones that don't depend on cached profiles: Test_06_KillProcessInTheMiddle, Test_07_RuleBindingApplyTest, Test_08_ApplicationProfilePatching, Test_10_MalwareDetectionTest, Test_11_EndpointTest, Test_15_CompletedApCannotBecomeReadyAgain, Test_18_ShortLivedJobTest.

In the node-agent logs:
```
"errorMessage":"container <cid> not found in container-profile cache"
```
→ 54 occurrences in Test_01 alone. Alerts that *do* fire (the false positives on `monitoring/` namespace containers) fire *without* a profile — meaning rule evaluation falls through as "unknown/missing profile" rather than "allowed per profile".

## 2. Root cause

`pkg/objectcache/containerprofilecache/containerprofilecache.go:178-213` — `addContainer`:

```go
cp, err := c.storageClient.GetContainerProfile(container.K8s.Namespace, cpName)
if err != nil {
    logger.L().Debug("ContainerProfile not yet available", ...)
    return nil                       // <-- BAILS; no entry ever created
}
if cp == nil {
    logger.L().Debug("ContainerProfile missing from storage", ...)
    return nil                       // <-- same
}
```

**The new cache never retries the initial CP GET.** `addContainer` runs when the container-collection fires `EventTypeAddContainer`. At that moment, the `ContainerProfile` CR usually **does not yet exist in storage** — it is created asynchronously by `containerprofilemanager` after observing the container's behavior. Typical ordering from the failing run:

```
10:26:21  container-collection fires EventTypeAddContainer → addContainer runs
10:26:21  storage.GetContainerProfile returns 404 "not yet available"
10:26:21  addContainer returns nil — NO cache entry stored
10:27:25  containerprofilemanager writes CP to storage (~60s later)
          CP exists in storage FOREVER AFTER, but the cache still has no entry
10:30:12  test's workload AP/NN reach "completed"
10:30:42+ test runs anomalous execs → rule evaluator calls GetContainerProfile → nil
10:30:42+ rule evaluation short-circuits / falls through as "no profile"
          → ls on `server` not flagged; curl ebpf.io on `nginx` not flagged
10:33:23  test asserts alerts present → fails, "All alerts: []"
```

The reconciler does not recover. `pkg/objectcache/containerprofilecache/reconciler.go:124-151`:

```go
func (c *ContainerProfileCacheImpl) refreshAllEntries(ctx context.Context) {
    ...
    c.entries.Range(func(id string, e *CachedContainerProfile) bool { ... })
    // Only iterates EXISTING entries. Containers whose addContainer bailed
    // on 404 are not in `entries`, so they never get a retry.
}
```

`reconcileOnce` only *evicts*, it does not *populate*.

## 3. Contrast with legacy behavior

`pkg/objectcache/applicationprofilecache/applicationprofilecache.go:83-267` `periodicUpdate` → `updateAllProfiles`:

1. Every `ProfilesCacheRefreshRate` (minutes):
2. Enumerate namespaces from `containerIDToInfo` (populated on `EventTypeAddContainer`)
3. For each namespace: `ListApplicationProfiles` (paginated)
4. For each returned profile: match by `workloadID` against `containerIDToInfo`
5. If match and profile is complete: `GetApplicationProfile` → `workloadIDToProfile.Set`

Key property: **legacy polls storage repeatedly for profiles covering containers it has already seen, even when no profile exists yet.** A CP created 60s after container start is picked up on the next tick.

The new cache's `refreshAllEntries` only refreshes entries that *already* got a successful initial GET. There is no equivalent of the legacy "scan for new profiles" tick.

## 4. Why the existing tests didn't catch this

The unit tests in `pkg/objectcache/containerprofilecache/` all preload the stub `storage.ProfileClient` with a valid CP *before* calling `addContainer`, so the 404-at-startup path is never exercised. Specifically:
- `containerprofilecache_test.go` → `fakeProfileClient{cp: cp}` — always returns cp
- `reconciler_test.go` T8 — populates the entry first, then mutates storage

The integration tests in `tests/containerprofilecache/` (T2, T5, T7) all pre-populate entries via `SeedEntryForTest` or prime the stub storage before calling `addContainer` — same gap.

**Plan v2 §2.7's T1 "golden-trace behavioral parity" test is exactly what would have caught this**, and it was explicitly deferred as a release-checklist item. The component-test suite is (retrospectively) the closest proxy for T1 that exists today, and it's failing for this reason.

## 5. Why the plan didn't predict this

Plan v2 §2.3 "Populate (EventTypeAddContainer)" step 5 says:
> `storageClient.GetContainerProfile(namespace, cpName)` — requires extending `storage.ProfileClient` with `GetContainerProfile` only; `ListContainerProfiles` dropped.

It dropped `List` under the assumption that every populate path can point-lookup by deterministic name. That's true — but it missed that the CP **may not exist yet** at container-start time, and dropped the repeated scan that legacy used to recover.

Plan v2 §2.6 reconciler text discusses "freshness" but only in the sense of re-fetching *existing* entries. The "never-yet-populated" case isn't covered.

The architect's Phase 4 review spotted adjacent issues (lock race, metrics dedup) but did not catch this because the planning documents framed the problem as "freshness of existing entries" not "initial-populate retry".

## 6. Recommended fix

Three options, in increasing invasiveness:

### Option A — Retry loop inside `addContainer` (smallest diff, ~30 LOC)

Wrap the `GetContainerProfile` call in a backoff retry with a capped duration:

```go
cp, err := backoff.Retry(ctx, func() (*v1beta1.ContainerProfile, error) {
    cp, err := c.storageClient.GetContainerProfile(namespace, cpName)
    if err != nil || cp == nil {
        return nil, fmt.Errorf("CP %s/%s not yet in storage", namespace, cpName)
    }
    return cp, nil
},
    backoff.WithBackOff(backoff.NewExponentialBackOff()),
    backoff.WithMaxElapsedTime(9*time.Minute),  // under the 10-min addContainerWithTimeout cap
)
```

Pros: minimal change, matches existing `waitForSharedContainerData` pattern (line 374-381), contains all the retry logic inside the per-container goroutine that `addContainerWithTimeout` already manages.

Cons: one long-lived goroutine per pending container for up to 9 minutes. The 10-min `addContainerWithTimeout` cap already blesses this order of magnitude, but N pending × 9 minutes × per-goroutine stack = O(N) goroutines blocking on backoff. For a node with 200 ephemeral containers starting in a burst, this is 200 live goroutines. Acceptable for a node-agent but worth measuring under the T3 replica-heavy benchmark.

### Option B — Track pending containers + retry in the reconciler (~100 LOC)

Add a `pending maps.SafeMap[string, *pendingContainer]` on `ContainerProfileCacheImpl`. `addContainer` on 404 records the `(namespace, cpName, sharedData, container)` tuple there. The reconciler's tick calls `retryPendingEntries(ctx)` that iterates `pending`, re-attempts the GET for each, and promotes to `entries` on success. Remove from `pending` on success or on eviction.

Pros: Mirrors legacy's periodic-scan behavior; bounded goroutine count (one reconciler); retries are cheap (just a cache lookup). Scales cleanly.

Cons: More code. Need to GC `pending` entries for containers that stopped (the existing `reconcileOnce` eviction logic needs to also scan `pending`).

### Option C — Revert to a List-based initial scan (~150 LOC)

Restore a `ListContainerProfiles` method on `storage.ProfileClient`, give the reconciler a "populate missing" half that scans by namespace and matches containers seen in `containerIDToInfo`-equivalent. This most closely mirrors the legacy shape.

Pros: Maximum parity with legacy behavior; no per-container retry state.

Cons: Plan explicitly dropped `ListContainerProfiles`; adding it back reopens the "point-lookup by deterministic name" simplification. Heavier storage load (list-per-namespace instead of get-per-container).

**Recommendation: Option B.** Keeps the point-lookup simplification, scales predictably, and localizes the fix to the reconciler. Estimate: ~100 LOC + 2-3 unit tests + 1 integration test that explicitly exercises the "CP created after container-add" ordering.

## 7. Test coverage gaps this uncovered

Before re-running the component tests, add these unit/integration tests:

1. **`TestAddContainer_CPCreatedAfterAdd` (unit)**: stub storage that returns 404 on the first `GetContainerProfile`, then returns a valid CP on the second call. Call `ContainerCallback(EventTypeAddContainer)`, advance the reconciler, assert `GetContainerProfile(id)` returns non-nil *after* the next tick.
2. **`TestReconcilerPromotesPendingToActive` (unit)**: directly drive the pending→active promotion under the new Option-B design.
3. **Integration analogue in `tests/containerprofilecache/`**: realistic scenario with controlled storage delay, asserts the cache enters the "running with profile" state within `2 * reconcileEvery`.

Once Option B is in place, the T8 integration test should be extended to cover the startup-race case.

## 8. Other (minor) items visible in the failing logs

Not blocking, but worth noting:

- **False positives for `monitoring` namespace containers**: 54 "container not found" errors in Test_01 alone, all for `prometheus-operator` / `prometheus` / `config-reloader` containers. Same root cause (cache never populated), different blast radius — these show up as noisy `Unexpected service account token access` alerts for routine k8s workloads.

- **`errorMessage` field on alert `profileMetadata`**: the alert still fires with `"failOnProfile":false, "profileDependency":1, "errorMessage":"container X not found in container-profile cache"`. This is intentional legacy behavior (alert with "unknown profile" annotation). Once the fix lands, this message should largely disappear for real workloads; if it persists for init containers in their brief pre-CP window, that's acceptable.

## 9. Action items before merge

- [ ] Implement Option B (reconciler-tracked pending-containers retry)
- [ ] Add `TestAddContainer_CPCreatedAfterAdd` unit test
- [ ] Add integration test with controlled storage delay
- [ ] Re-run component tests on PR — expect all 13 now-failing tests to pass
- [ ] Keep the Phase-4 follow-up items (`containerprofile-cache-followups.md`) as-is — this is a *new* follow-up, not a modification of existing ones

## 10. References

- **PR**: https://github.com/kubescape/node-agent/pull/788
- **Failing run**: GitHub Actions run 24773018102, job 72484839197 (Test_01)
- **Buggy file**: `pkg/objectcache/containerprofilecache/containerprofilecache.go:178-213`
- **Missing retry in**: `pkg/objectcache/containerprofilecache/reconciler.go:124-151`
- **Legacy reference**: `pkg/objectcache/applicationprofilecache/applicationprofilecache.go:83-267` (in git history, file deleted in step 8 at commit `71167cff`)
- **Plan blind spot**: `.omc/plans/containerprofile-cache-unification-plan-v2.md` §2.3 step 5 + §2.6 refresh loop
