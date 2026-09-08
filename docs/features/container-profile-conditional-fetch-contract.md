# Container Profile Conditional-Fetch Contract

`storage.ProfileClient` fetches a container's learned `ContainerProfile` by name:

```go
GetContainerProfile(ctx context.Context, namespace, name string) (*v1beta1.ContainerProfile, error)
```

A remote implementation of this interface can often answer "the body you already have is still current" far more cheaply than it can re-stream an identical profile. That answer needs two things the signature above has no room for: a **validator** the caller sends, and a way to say **"unchanged"** instead of returning a body.

This document describes the vocabulary node-agent exports so a remote implementer can do that, and the guard the reconciler applies before it ever asks. It covers only node-agent's half — the transport that carries the signal off-node is the implementer's concern.

## Why the signal travels out-of-band

`ProfileClient` has a second implementer with no concept of a remote checksum: the in-cluster CRD/aggregated-API client at `pkg/storage/v1/storage.go` (`var _ storage.ProfileClient = (*Storage)(nil)`). Adding a parameter or a return value for a capability only one implementer has would touch every implementer, every mock, and the six-odd test files that declare conformance.

So the request travels on the `context.Context` and the response as a sentinel `error` plus an `ObjectMeta` annotation. The interface signature is unchanged, and the in-cluster implementer changes by **zero lines** — it never attaches a checksum, never returns the sentinel, and behaves exactly as before.

A narrower optional interface discovered by type assertion was considered and rejected: a type assertion fails *silently* when an implementer drifts out of conformance (the fast path just quietly stops engaging), and it does not survive the wrapper layers this call already passes through. A context value and a wrapped error propagate through wrappers for free.

## The exported vocabulary

All four symbols live in `pkg/storage/checksum.go`, next to the interface they extend. That package imports no client library of any kind, which is what keeps `pkg/objectcache` free of transport dependencies.

| Symbol | Type | Value / signature |
|---|---|---|
| `storage.ContainerProfileChecksumAnnotationKey` | `const string` | `"backend.kubescape.io/container-profile-checksum"` |
| `storage.ErrProfileUnchanged` | `var error` | `errors.New("container profile unchanged")` |
| `storage.WithKnownChecksum` | `func` | `(ctx context.Context, checksum string) context.Context` |
| `storage.KnownChecksumFromContext` | `func` | `(ctx context.Context) string` |

The context key is an unexported `knownChecksumKey struct{}`, so no other package can collide with it or forge a value.

### Request: `WithKnownChecksum`

The reconciler attaches the checksum of the profile it already holds to the context of a single `GetContainerProfile` call. An implementer reads it with `KnownChecksumFromContext`; `""` (the value for a bare context) means **send the body unconditionally**. An implementer that ignores the value entirely is always correct — it just returns the body, as today.

The checksum is attached **per call, never to a shared parent context**. It is a claim about one specific object, and `refreshOneEntry` fetches two different objects from contexts derived from the same parent.

### Response: `ErrProfileUnchanged`

An implementer that confirmed the caller's checksum still matches returns `(nil, ErrProfileUnchanged)` — no profile, because none was transferred. The reconciler matches it with `errors.Is`, so it may be wrapped.

Returning this sentinel for a request that carried **no** checksum is a protocol violation: it claims a match against a validator the caller never supplied. The reconciler tracks `validatorOffered` for the exact call and accepts the sentinel only when that flag is true. An unsolicited sentinel is logged as a warning, counted as `protocol_error`, and handled like a transient failure: the existing entry stays in place, but the response does not consume an unchanged allowance or clear a forced-revalidation debt.

### Response: the checksum annotation

On a **normal** fetch, an implementer stamps the profile's current checksum onto `ObjectMeta.Annotations` under `ContainerProfileChecksumAnnotationKey`. This is the only channel back through the unchanged signature, and it is what lets an entry acquire the validator it will offer on a later tick. Without it the whole mechanism is permanently inert.

The canonical remote validator is `sha256:<64 lowercase hexadecimal characters>`. Node-agent treats the complete value as opaque: it neither parses nor prefixes it, and compares/returns it byte-for-byte. The backend's API boundary owns conversion from a raw stored SHA-256 value into this canonical wire form. Keeping normalization at that boundary prevents different `ProfileClient` adapters from inventing incompatible validators.

The key is namespaced under `backend.kubescape.io` specifically so it cannot collide with the learning-lifecycle annotations in `k8s-interface/instanceidhandler/v1/helpers` that this cache reads for status and completion (`StatusMetadataKey`, `CompletionMetadataKey`).

### Cross-repo key agreement

The annotation key is a **string contract between repositories**, and it fails silently rather than loudly if the two sides disagree — nothing errors, the cache simply never observes a checksum and every fetch stays unconditional.

The remote implementer today is `armosec/private-node-agent`'s backend adapter (`pkg/backend/storage.go`), which wraps `kubescape/backend`'s `StorageClient`. That client stamps its own constant, `backendv1.ContainerProfileChecksumAnnotationKey`, whose value is the identical string `"backend.kubescape.io/container-profile-checksum"`. The adapter is responsible for translating the backend's vocabulary onto node-agent's — re-keying the annotation if the two ever diverge, and mapping the backend's own unchanged-sentinel onto `storage.ErrProfileUnchanged` so `errors.Is` matches here.

Treat the value as frozen. Changing it on one side only is not a compile error.

## Where the validator is stored

`CachedContainerProfile.Checksum` (`pkg/objectcache/containerprofilecache/containerprofilecache.go`) holds the content checksum of the **learned** CP at last load, read via `checksumOfCP` (`reconciler.go`, mirroring `rvOfCP`). It is best-effort: empty whenever the source supplied no annotation, which is always the case for the in-cluster implementer.

Two properties are easy to get wrong and are both covered by tests in `reconciler_checksum_test.go`:

- **Both construction sites populate it.** `rebuildEntryFromSources` is the obvious one, but `buildEntry` (reached from `tryPopulateEntry` and the pending-promotion retry) matters more. A profile that never changes is built once by `buildEntry` and thereafter always returns at `refreshOneEntry`'s fast-skip, never reaching `rebuildEntryFromSources`. Populating only the rebuild path would leave `Checksum` empty forever for exactly the steady-state profiles this exists for — with every test still green.
- **It tracks the learned CP, never an adopted authored one.** On the adoption path `tryPopulateEntry` repoints `cp` at the authored profile *before* calling `buildEntry`, so the value is corrected after the call from a checksum captured beforehand — the same shape as the existing `entry.RV = learnedRV` correction, and for the same reason: the validator is offered back on a `GET` of the learned slug, so it must describe that object.
- **It participates in fast-skip invalidation.** Matching ResourceVersions are not sufficient for remote objects, where RV may remain empty or unchanged across different bodies. `checksumOfCP(cp) == e.Checksum` must also hold. This rebuilds on changed content and on first checksum acquisition even when both RV values match.

Each entry also carries an unexported consecutive-unchanged count. Ten valid `ErrProfileUnchanged` responses may be accepted in sequence. The next otherwise-eligible refresh suppresses the validator and forces a body. Only a successful learned-profile body resets the count, including a byte-identical body that later takes the fast-skip; transport errors and unsolicited sentinels leave the force-due state intact. This bounds exposure to an incorrectly accepted or stale remote validator to ten refresh intervals without adding public configuration.

## Validator eligibility and forced revalidation

`refreshOneEntry` does more than refresh the learned CP: it also re-fetches the user-authored CP, propagates projection-spec changes, and refreshes the entry's cached lifecycle state. A conditional fetch is only legitimate when the body is genuinely not needed for any of that. The reconciler first snapshots the projection-spec hash and computes eligibility:

```go
validatorEligible := e.UserCPRef == nil && e.UserCPRV == "" && e.SpecHash == preFetchSpecHash &&
    e.State != nil && e.State.Status == helpersv1.Completed && e.State.Completion == helpersv1.Full
```

| Condition | Why |
|---|---|
| `e.UserCPRef == nil` | An authored CP is re-fetched and re-adopted this tick, so the body is needed regardless. |
| `e.UserCPRV == ""` | `UserCPRef == nil` alone does not establish the fast-skip's `rvsMatchCP(userDefinedCP, e.UserCPRV)`, which with no authored CP present reduces to `rvsMatchCP(nil, e.UserCPRV)` — true only for `""`. Without this, an entry in the `authoredJustDropped` shape (an authored RV on record but no authored CP any more) could skip that handling. |
| `e.SpecHash == preFetchSpecHash` | The projection spec moved before the request, so the entry must be re-projected from a real body even if the content is identical. |
| state is `Completed` + `Full` | The lifecycle annotations sit **outside** the content checksum, so a profile finishing its learning period presents an unchanged checksum. Without this condition the entry could keep answering "unchanged", preventing the rebuild that refreshes `e.State`. |

Request mode is then selected from a closed set. A missing checksum takes `missing`; a present checksum with failed eligibility takes `ineligible`; an eligible entry at the ten-response bound takes `forced_revalidation`; otherwise the checksum is attached and the mode is `offered`. Only the last case sets `validatorOffered`.

Every condition has a negative test asserting that no checksum is sent when it fails, and the forced-revalidation tests pin the ten-response boundary and recovery behavior.

### Why the state conjunct is not optional

`entry.State` is not internal bookkeeping. `pkg/rulemanager/rule_manager.go`'s `HasFinalApplicationProfile` gates on `state.Status == helpersv1.Completed && state.Completion == helpersv1.Full`, and `pkg/rulemanager/ruleadapters/creator.go` stamps `FailOnProfile` and the reported profile status onto every alert built from it. Delaying that state transition would make a finished profile keep alerting as partial until the forced body arrives.

State staleness has a more direct effect than RV staleness: `e.RV` is bookkeeping, while `e.State` changes whether rulemanager considers the profile final and how alerts are stamped. Forced revalidation bounds both, but the state guard keeps lifecycle transitions immediate rather than delaying them for as many as ten refresh intervals.

The predicate is `Completed` + `Full` rather than `isTerminalCPStatus` (which also admits `TooLarge`) deliberately: it is the exact state rulemanager treats as final, and the only one from which no further lifecycle transition is expected. A `TooLarge` profile simply keeps fetching bodies — a lost optimization, not a correctness risk.

The spec hash has two snapshots with deliberately different roles. `preFetchSpecHash` decides whether a validator may be offered. Immediately before the fast-skip, `postFetchSpecHash` is read again; the skip requires `e.SpecHash == postFetchSpecHash`. A projection-spec replacement that lands during a body fetch therefore rebuilds the entry under the new spec instead of preserving the old projection. If a spec replacement overlaps a valid unchanged response, its nudge is retained by the trailing-edge scheduler described below and the following pass fetches the body because the entry is then ineligible.

## Handling the sentinel

`refreshOneEntry` checks `errors.Is(cpErr, storage.ErrProfileUnchanged)` before `apierrors.IsNotFound`, but accepts it only when `validatorOffered` is true for that exact request. A valid response keeps the same cache-entry pointer, leaves its projected data, RV, and checksum unchanged, increments the consecutive-unchanged count, and records the `unchanged` outcome. An unsolicited response records `protocol_error` and follows the transient-failure policy without advancing or resetting that count.

The explicit branch is load-bearing, not cosmetic. Without it, a sentinel that also carries a not-found shape would fall into the not-found path, which sets `cp = nil`, finds no authored CP either, and **evicts the entry**. A sentinel that does not carry a not-found shape would instead land in the generic transient-error path — which happens to keep the entry, but logs it as a fetch failure, making a successful optimization indistinguishable from a broken connection.

### Accepted freshness divergence

A checksum match proves the **content** is byte-identical. It does not prove `ResourceVersion` equality: RV can bump on a metadata-only write, and annotations are outside the content checksum. On a sentinel response the client never sees the new object, so **`e.RV` keeps its previous value**.

This one is deliberate and bounded. Every consumer downstream of this cache reads the projected *content*; `e.RV` serves only as a change detector. The forced full-body request after ten valid unchanged responses refreshes RV and state even if the content checksum remains stable. Including annotations in the checksum would defeat the optimization entirely, since the learning pipeline rewrites them continuously. Tests pin both the temporary RV staleness and the revalidation bound.

The cached `State` still stays on the unconditional path until it is `Completed` + `Full`; this avoids waiting up to ten intervals for a learning-lifecycle transition that directly affects enforcement.

## Refresh scheduling

Periodic ticks and projection-spec nudges both call `scheduleRefresh`. It is a trailing-edge single-flight scheduler: the first request starts one worker, requests arriving during a pass set a pending bit, and the worker drains that bit with one more pass after the active pass finishes. Multiple overlapping requests coalesce, but none can be stranded.

A mutex protects both pending state and worker ownership. In particular, checking that no trailing work remains and marking the worker idle are one atomic handoff. This closes the race where a request could otherwise arrive after the final pending check but before an atomic in-progress flag was cleared. Ticker handling still performs eviction and pending-entry retry work before it schedules refresh; only the profile-refresh pass is consolidated.

This matters for spec changes: a nudge received while a ticker-owned refresh is blocked must revisit entries that the active pass already processed under the old spec. One scheduler test blocks the second profile fetch, nudges after the first was processed, and verifies a single non-overlapping trailing pass rebuilds both entries under the new spec. A second test places a request at the final pending/idle handoff and verifies it always produces another pass.

## Metrics

The following counters are always on; they are not gated by `profileProjection.detailedMetricsEnabled`:

| Metric | Attribute | Closed values |
|---|---|---|
| `node_agent.profile.conditional_fetch.requests.total` | `mode` | `offered`, `missing`, `ineligible`, `forced_revalidation` |
| `node_agent.profile.conditional_fetch.responses.total` | `outcome` | `body`, `unchanged`, `not_found`, `error`, `protocol_error` |

They intentionally carry no container, namespace, profile name, checksum, or error-text attributes. `missing` makes an annotation-key mismatch or adapter omission visible; `protocol_error` makes an unsolicited sentinel visible; and `forced_revalidation` shows that the safety bound is active.

## Current status in this repo

No in-tree `ProfileClient` implementer returns `ErrProfileUnchanged`. The in-cluster client supplies no checksum annotation, so its refreshes remain unconditional and are observed as `mode="missing", outcome="body"`. Checksum-aware invalidation and the unified scheduler still apply to every implementation; an out-of-tree remote adapter can opt into body omission without changing the interface.
