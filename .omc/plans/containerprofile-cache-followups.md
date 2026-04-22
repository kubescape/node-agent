# ContainerProfile Cache Unification — Follow-up PRs

**Parent PR**: branch `cp-cache`, HEAD `c2966c08`. 10 commits; see `containerprofile-cache-unification-consensus.md` for the approved plan.

**Context**: The parent PR is functionally complete and mergeable. Phase 4 review flagged two items that are architecturally acceptable for merge but warrant dedicated follow-up work. Two plan-deferred test baselines also need retroactive capture once the parent PR is merged.

Resume order below is linear — each PR stands alone, no cross-blocking.

---

## PR 2 — Storage `ProfileClient` context propagation

**Priority**: Medium. No production bug, but removes a class of SLO-violation risks the reconciler can't currently bound.

**Problem**: `pkg/storage/storage_interface.go:10-16` ProfileClient methods don't take `ctx`. Implementation at `pkg/storage/v1/containerprofile.go:12` uses `context.Background()`. Reconciler has `ctx` but can't thread it:

```go
// pkg/objectcache/containerprofilecache/reconciler.go refreshOneEntry
func (c *ContainerProfileCacheImpl) refreshOneEntry(_ context.Context, id string, ...) {
    cp, err := c.storageClient.GetContainerProfile(e.Namespace, e.CPName)
    // ctx dropped on the floor; can't cancel mid-RPC, can't enforce per-call budget
}
```

Consequence: a slow k8s API server can hang one Get for the backoff window (~10 min cap); `ctx.Err()` checks between RPCs are cosmetic because the *current* RPC isn't cancellable. At 300 containers × 30s tick × overlay path = up to 900 sequential uninterruptible Gets per refresh burst.

**Scope — Level 2 (clean break)**: Replace all 5 ProfileClient methods with `ctx`-first signatures:

```go
type ProfileClient interface {
    GetApplicationProfile(ctx context.Context, namespace, name string) (*v1beta1.ApplicationProfile, error)
    GetNetworkNeighborhood(ctx context.Context, namespace, name string) (*v1beta1.NetworkNeighborhood, error)
    GetContainerProfile(ctx context.Context, namespace, name string) (*v1beta1.ContainerProfile, error)
    ListApplicationProfiles(ctx context.Context, namespace string, limit int64, cont string) (*v1beta1.ApplicationProfileList, error)
    ListNetworkNeighborhoods(ctx context.Context, namespace string, limit int64, cont string) (*v1beta1.NetworkNeighborhoodList, error)
}
```

Files to touch (~15):
- `pkg/storage/storage_interface.go` — interface
- `pkg/storage/v1/{applicationprofile,networkneighborhood,containerprofile}.go` — impls
- `pkg/storage/storage_mock.go` — test mock
- `pkg/objectcache/containerprofilecache/{containerprofilecache,reconciler}.go` — thread ctx in
- `pkg/containerprofilemanager/v1/monitoring.go` — production writer (not a cache consumer, but consumes the same interface)
- Any test files using the mock

**Bonus with small extra scope (Level 3)**: add a per-call RPC budget wrapper in the reconciler to enforce SLO directly:

```go
// Proposed wrapper in reconciler.go
func (c *ContainerProfileCacheImpl) refreshRPC(ctx context.Context, fn func(context.Context) error) error {
    ctx, cancel := context.WithTimeout(ctx, c.rpcBudget) // default 5s, overridable via config
    defer cancel()
    return fn(ctx)
}
```

Config key: add `RPCBudget time.Duration` to `pkg/config/config.go`, default 5s.

**Acceptance**:
- All 5 methods accept ctx as first arg
- Reconciler threads `ctx` into every Get call
- Existing tests updated; `go test -race ./...` clean
- New test: `TestRefreshHonorsContextCancellationMidRPC` — stub storage that blocks in `GetContainerProfile`, cancel ctx, assert refresh returns within 100ms

**Estimated diff**: ~200 LOC across 15 files.

---

## PR 3 — Read-only ContainerProfile wrapper + race-fuzz test

**Priority**: Medium-low. Corruption risk requires a future contributor to mutate the shared pointer, which they won't do if the type forbids it.

**Problem**: `pkg/objectcache/containerprofilecache/containerprofilecache.go:43-46` documents the invariant that `entry.Profile` is read-only once stored, but the type system doesn't enforce it. `GetContainerProfile(id)` returns `*v1beta1.ContainerProfile` which exposes every writeable slice/map field. A consumer doing `cp.Spec.Execs = append(cp.Spec.Execs, ...)` silently corrupts the cache for all other readers of the same shared pointer (plan's Option A+ fast-path, §2.3 step 7).

**Why not fixed in parent PR**:
- DeepCopy-on-read defeats T3's ≤+20% replica-heavy memory regression gate (plan v2 §2.7) — exactly what Option A+ was designed to avoid
- ReadOnlyCP wrapper needs all 20+ CEL call sites retouched — too much extra surface in the migration PR

**Two-part scope**:

### Part A — race-fuzz test (low effort, catches regressions immediately)

New test at `tests/containerprofilecache/shared_pointer_race_test.go`:

```go
func TestSharedPointerReadersDoNotCorruptCache(t *testing.T) {
    // 1. Populate entry with a CP that has non-empty Execs/Opens slices
    // 2. Spawn N=50 goroutines that each call cpc.GetContainerProfile(id)
    //    in a loop and read (but not write) Spec.Execs/Opens
    // 3. Simultaneously run reconciler.refreshAllEntries(ctx) in another goroutine
    //    that rebuilds the entry with fresh RVs
    // 4. Run for 500ms under -race; assert:
    //    - no data races detected
    //    - all reader goroutines observed either the old or new pointer, never a mid-mutation state
    //    - no reader goroutine's slice was mutated out from under it
    // 5. Optional: run with a deliberately-mutating reader in a fail-only subtest
    //    to prove the race detector catches the anti-pattern
}
```

Must run as part of `make test` with `-race`. ~80 LOC.

### Part B — ReadOnlyCP wrapper type (cleaner but more invasive)

Introduce `type ReadOnlyContainerProfile` in `pkg/objectcache/containerprofilecache/readonly.go`:

```go
type ReadOnlyContainerProfile interface {
    GetExecs() []v1beta1.ExecCalls       // returns slices.Clone or a defensive copy
    GetOpens() []v1beta1.OpenCalls
    GetCapabilities() []string
    GetSyscalls() []string
    GetEndpoints() []v1beta1.HTTPEndpoint
    GetPolicyByRuleId() map[string]v1beta1.RulePolicy
    GetIngress() []v1beta1.NetworkNeighbor
    GetEgress() []v1beta1.NetworkNeighbor
    GetLabelSelector() metav1.LabelSelector
    GetImageID() string
    GetImageTag() string
    GetAnnotations() map[string]string  // for SyncChecksumMetadataKey lookup
    GetName() string                    // for ProfileState.Name parity
    GetResourceVersion() string         // for RV-based assertions in tests
}
```

Change `objectcache.ContainerProfileCache` interface:
```go
GetContainerProfile(id string) ReadOnlyContainerProfile  // was *v1beta1.ContainerProfile
```

Touches:
- `pkg/objectcache/containerprofilecache_interface.go` — interface + mock
- `pkg/objectcache/containerprofilecache/containerprofilecache.go` — `GetContainerProfile` impl returns wrapper; test hook `SeedEntryForTest` unchanged
- `pkg/rulemanager/profilehelper/profilehelper.go:15-25` — `GetContainerProfile` return type
- `pkg/rulemanager/rule_manager.go:202, 340, 399` — adapt reads
- `pkg/rulemanager/rulepolicy.go:23` — `Validate(ruleId, process string, cp ReadOnlyContainerProfile)` — reads `cp.GetPolicyByRuleId()[ruleId]`
- `pkg/rulemanager/ruleadapters/creator.go:148, 165` — state reader unchanged (State is a separate struct, not the profile itself)
- 20 CEL call sites across `pkg/rulemanager/cel/libraries/{applicationprofile,networkneighborhood}/*.go` — swap `cp.Spec.X` → `cp.GetX()`
- `pkg/objectcache/v1/mock.go` — `RuleObjectCacheMock.GetContainerProfile` returns wrapper
- CEL test fixtures — update mock CP construction

**Acceptance**:
- Compile-time enforcement: `*v1beta1.ContainerProfile` cannot be obtained through `ContainerProfileCache` interface
- All 20 CEL callers use accessor methods
- `go test -race ./...` clean
- Part A's race-fuzz test still passes (belt-and-suspenders)

**Estimated diff**: Part A ~80 LOC. Part B ~300 LOC across ~30 files.

**Recommendation**: Ship Part A immediately in a small PR. Part B can follow only if the race-fuzz ever catches a real violation, or as a hygiene sweep during the next sprint.

---

## PR 4 — Release-checklist items (T1 parity + T3 memory)

**Priority**: Required before production rollout announcement. Not release-blocking if rollout is gradual.

Plan v2 §2.7 explicitly marked these as release-checklist items, not CI-gated — but they still need to happen. They couldn't be done in the parent PR because both require a pre-migration baseline that can no longer be captured from `cp-cache`.

### T1 — Golden-trace behavioral parity

Plan v2 §2.8 step 1: *"Capture parity baseline on main HEAD — BEFORE step 2. Run today's rulemanager against `fixtures/golden-trace.json`, capture alerts, commit `fixtures/golden-alerts.json` with the main commit SHA in the test comment."*

**Gap**: step 1 was never actually done in the parent PR. The commit `949f3699` titled "feat: foundation (steps 1, 2, 5-early)" did step 1-lite (fixture plumbing) but didn't capture the baseline from pre-migration main.

**Resume path**:
1. Check out `main` (pre-`949f3699^` state) in a throwaway worktree
2. Construct or synthesize a representative k8s+ebpf event trace (`fixtures/golden-trace.json`)
3. Run `rulemanager` + `ruleCooldown` + `CEL evaluator` against the trace; capture the alert stream as `fixtures/golden-alerts.json`
4. Commit the fixtures with the `main` SHA in a comment
5. On `cp-cache` (or main-post-merge), add `tests/containerprofilecache/parity_golden_test.go` that replays `fixtures/golden-trace.json` through the new cache and deep-equals the alert stream against `fixtures/golden-alerts.json` (timestamp-ordered)
6. If they diverge, **human-review the diff** before accepting — plan v2 risk R1 explicitly warns that a buggy baseline will canonicalize the bug

**Acceptance**: T1 passes; PR gated. Human sign-off on any diff delta.

### T3 — Memory footprint benchmark

Plan v2 §2.7 §2.8: *"ephemeral-heavy ≥10% reduction AND replica-heavy ≤+20% regression vs legacy baseline"*

**Gap**: Legacy caches are deleted; baseline is gone from HEAD.

**Resume path**:
1. Check out `main` in a throwaway worktree
2. Write `BenchmarkLegacyMemory` that reproduces the two reference workloads from plan v2 §2.7 (ephemeral-heavy: 30 pods × 1 init + 2 regular; replica-heavy: 10 Deployments × 5 replicas × 3 containers)
3. Run `go test -bench -benchmem`, capture `HeapInuse` after GC settle
4. On `cp-cache`, add `tests/containerprofilecache/memory_bench_test.go` that reproduces the same two workloads against the new cache
5. Commit both numeric baselines as constants with reference commit SHAs in comments
6. Assert: ephemeral-heavy ≤ 0.90× legacy baseline, replica-heavy ≤ 1.20× legacy baseline
7. Wire into `make bench` or similar (not part of `make test` default — expensive)

**Acceptance**: Both thresholds met; PR can be reference for production rollout note.

### RSS measurement on real kind cluster

Plan v2 R8 + §2.9 rollout: release-notes item. Run the parent PR's branch on a real kind cluster with the ephemeral-heavy workload, capture node-agent RSS over 10 minutes, include in release notes template. Not a Go test — an ops validation.

---

## Additional leftover items (not tracked as PRs)

Small items from Phase 4 review that are either plan-accepted or pure polish; pick up only if touching nearby code:

- **Typed nil helpers `apRV` / `nnRV`** (architect low #3): replace `rvOrEmpty(metav1.Object)` at `reconciler.go:303-329` with two type-safe helpers. Eliminates the typed-nil-interface trap. ~15 LOC.
- **T8 location**: currently at `pkg/objectcache/containerprofilecache/reconciler_test.go:414` (unit-level). Plan expected `tests/containerprofilecache/`. Either move or mirror. ~60 LOC.
- **`HasFinalApplicationProfile` → `HasFinalContainerProfile`** (plan v2 §2.4): external `RuleManagerInterface` rename. Consumed by `pkg/nodeprofilemanager/v1/nodeprofile_manager.go:111`. Do after user-AP authoring is formally retired (follow-on plan §5 "Follow-ups").
- **Mock setter contract documentation** (code-reviewer P1 #3): `pkg/objectcache/v1/mock.go` `SetApplicationProfile` + `SetNetworkNeighborhood` both write into `r.cp.Spec`. They partition cleanly today, but the contract is fragile — add a top-of-file comment spelling out "first-container-wins, AP-fields and NN-fields must remain non-overlapping". ~10 LOC.
- **User-facing migration docs** (plan v2 ADR §4 Follow-ups): announce user-AP/NN CRD deprecation, pointing at `nodeagent_user_profile_legacy_loads_total{kind,completeness}` metric for operators. Docs-only PR.

---

## Summary table

| PR | Priority | Effort | Blocks |
|----|----------|--------|--------|
| PR 2 — storage ctx propagation | Medium | ~200 LOC | Nothing |
| PR 3 Part A — race-fuzz test | Low | ~80 LOC | Nothing |
| PR 3 Part B — ReadOnly wrapper | Low-medium | ~300 LOC | Only if Part A catches a real race |
| PR 4 T1 — golden parity | **Required before announcement** | 1 day | Release notes |
| PR 4 T3 — memory bench | **Required before announcement** | 1 day | Release notes |
| PR 4 RSS — ops validation | Required | 1 hour on kind | Release notes |

Resume from whichever has the most review-feedback pressure. PR 2 is the cleanest standalone; PR 4 T1/T3 need real-world work outside the IDE.
