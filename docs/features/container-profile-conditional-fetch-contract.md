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

Returning this sentinel for a request that carried **no** checksum is a protocol violation: it claims a match against a validator the caller never supplied. Implementers must reject that case with a distinct, loud error rather than the sentinel, so a client cache can never be frozen on the basis of nothing.

### Response: the checksum annotation

On a **normal** fetch, an implementer stamps the profile's current checksum onto `ObjectMeta.Annotations` under `ContainerProfileChecksumAnnotationKey`. This is the only channel back through the unchanged signature, and it is what lets an entry acquire the validator it will offer on a later tick. Without it the whole mechanism is permanently inert.

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

## The five-conjunct guard

`refreshOneEntry` does more than refresh the learned CP: it also re-fetches the user-authored CP, propagates projection-spec changes, and refreshes the entry's cached lifecycle state. A conditional fetch is only legitimate when the body is genuinely not needed for any of that. So the checksum is offered only when all five hold:

```go
e.UserCPRef == nil && e.UserCPRV == "" && e.SpecHash == currentSpecHash && e.Checksum != "" &&
    e.State != nil && e.State.Status == helpersv1.Completed && e.State.Completion == helpersv1.Full
```

| Conjunct | Why |
|---|---|
| `e.UserCPRef == nil` | An authored CP is re-fetched and re-adopted this tick, so the body is needed regardless. |
| `e.UserCPRV == ""` | `UserCPRef == nil` alone does not establish the fast-skip's `rvsMatchCP(userDefinedCP, e.UserCPRV)`, which with no authored CP present reduces to `rvsMatchCP(nil, e.UserCPRV)` — true only for `""`. Without this, an entry in the `authoredJustDropped` shape (an authored RV on record but no authored CP any more) could skip that handling. |
| `e.SpecHash == currentSpecHash` | The projection spec moved, so the entry must be re-projected from a real body even if the content is identical. |
| `e.Checksum != ""` | Nothing to validate against. Sending `""` would mean "unconditional" anyway, and a server answering "unchanged" to it would be the protocol violation described above. |
| state is `Completed` + `Full` | The lifecycle annotations sit **outside** the content checksum, so a profile finishing its learning period presents an unchanged checksum. Without this conjunct the entry would answer "unchanged" on that tick *and every later one* — the checksum stays valid indefinitely — so the rebuild that refreshes `e.State` would never run and the cached state would freeze permanently. |

Each conjunct has its own negative test asserting that no checksum is sent when it fails.

### Why the state conjunct is not optional

`entry.State` is not internal bookkeeping. `pkg/rulemanager/rule_manager.go`'s `HasFinalApplicationProfile` gates on `state.Status == helpersv1.Completed && state.Completion == helpersv1.Full`, and `pkg/rulemanager/ruleadapters/creator.go` stamps `FailOnProfile` and the reported profile status onto every alert built from it. A frozen state would make a finished profile keep alerting as partial forever.

Note the asymmetry with `e.RV` below: RV staleness self-corrects at the next unconditional fetch, whereas a frozen state has no next unconditional fetch — the condition that caused it also perpetuates it. That is why one is accepted and the other is guarded against.

The predicate is `Completed` + `Full` rather than `isTerminalCPStatus` (which also admits `TooLarge`) deliberately: it is the exact state rulemanager treats as final, and the only one from which no further lifecycle transition is expected. A `TooLarge` profile simply keeps fetching bodies — a lost optimization, not a correctness risk.

`currentSpecHash` is snapshotted **once, above the fetch**, and reused for both the guard and the later fast-skip, so the two decisions cannot disagree within a tick. The trade-off: a projection-spec swap landing *during* the fetch is noticed on the next tick rather than this one. That is self-healing — the next tick's `e.SpecHash != currentSpecHash` comparison forces the rebuild regardless.

## Handling the sentinel

`refreshOneEntry` matches `errors.Is(cpErr, storage.ErrProfileUnchanged)` **before** the `apierrors.IsNotFound` check and returns with the cache entry left completely untouched.

The explicit branch is load-bearing, not cosmetic. Without it, a sentinel that also carries a not-found shape would fall into the not-found path, which sets `cp = nil`, finds no authored CP either, and **evicts the entry**. A sentinel that does not carry a not-found shape would instead land in the generic transient-error path — which happens to keep the entry, but logs it as a fetch failure, making a successful optimization indistinguishable from a broken connection.

### Accepted freshness divergence

A checksum match proves the **content** is byte-identical. It does not prove `ResourceVersion` equality: RV can bump on a metadata-only write, and annotations are outside the content checksum. On a sentinel response the client never sees the new object, so **`e.RV` keeps its previous value**.

This one is deliberate and accepted. Every consumer downstream of this cache reads the projected *content*; `e.RV` serves only as a change detector for the next tick, where a stale-but-lower RV is conservative — it can cause an extra rebuild, never a missed one. Including annotations in the checksum would defeat the optimization entirely, since the learning pipeline rewrites them continuously. The behavior is pinned by a test that asserts the staleness *positively*, so it reads as intended rather than as a defect waiting to be found.

The cached `State` is a different matter and is **not** allowed to go stale: the guard's state conjunct keeps an entry on the unconditional path until its lifecycle has finished, precisely because that staleness would be permanent rather than bounded. See "Why the state conjunct is not optional" above.

## Current status in this repo

No in-tree `ProfileClient` implementer returns `ErrProfileUnchanged`, so within node-agent alone this is a contract with no observable behavior change: the guard evaluates, `e.Checksum` stays empty for the in-cluster client, and every fetch is unconditional exactly as before. The vocabulary exists so an out-of-tree implementer can opt in without any change to the interface or to the in-cluster client.
