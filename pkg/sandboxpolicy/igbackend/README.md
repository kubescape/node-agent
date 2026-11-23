# Execution-policy backend

The public service uses `NewFull` with the G020 shared node engine (below) and
`NewContainerdFullSource`; there is no other exec engine, and node-agent does
not use IG's legacy Owner API. The legacy `NewNative` / path-only converter
remains for historical tests, but is not a fallback for unsupported full
policies.

`FullBackend` installs immutable generation provenance before native startup or
publication. Kernel commit is irreversible even if reopening/finalization
fails; reconciliation resumes that generation rather than rolling it back.
Unsupported inputs are refused. Exact cgroups stay exclusively reserved until
actual detach and release; failed cleanup remains owned and retryable. The
trusted containerd client closes only after every lease has been consumed.

The combined lease pins the exact proc allocation, cgroup, workload mount
namespace, initial-host PID/mount namespaces, stable root and complete lower
image inode index. It authenticates containerd task/image/CRI metadata, never
policy annotations. The protected socket and administrator host mounts are
trusted deployment inputs, not proven authentic merely by their path names.
No inferred helper exemptions exist.

`FullVerdictCatalog` keeps at most 16 generation-specific decoders, including
active and staged provenance. Evicted/unknown generations are dropped rather
than attributed to a newer plan. Full verdicts use the kernel's typed four-word
match bitmap, with explicit incomplete matches for operational failures. UID,
argv, actor and image facts remain absent when the event does not supply them.
Exporter failures do not change kernel decisions.

No image is implicitly downloaded or trusted: the local OCI archive is
privileged administrator-supplied code, and IG skips its signature
verification for explicit local targets.

## Shared node engine (G020)

`sharedengine.go` implements `FullEngine` over one node-wide IG shared
collection, started lazily on the first binding. Two starts share it:

- product (`sharedengine_start_product.go`, default build):
  `NewSharedProductEngine` runs IG's product kernel gate
  (`fullruntime.SharedProductKernel`) at agent start, loads the one
  compiled-in image's profile and requires the trusted store to resolve the
  image to the pinned manifest digest; it runs the gate and binds the digest
  again before `StartNode`. It starts through `fullruntime.WithSharedNodeHost`.
  Any refusal, a malformed gate result included, leaves an engine that never
  starts and reports the reason (`SharedEngineUnavailable`).
  `NewUnavailableSharedEngine` builds such an engine for a refusal made at
  engine selection; a reason wrapping
  `ErrKernelNotQualified` is reported as `KernelNotQualified`;
- qualification (`sharedengine_start_qualification.go`, build tags
  `sandbox_shared_qualification` and IG's `enforce_exec_shared_qualification`):
  `NewSharedQualificationEngine` starts through the IG qualification seam and
  never reports Ready.

Start binds the trusted cgroup/init/CRI container ID; Activate and `UpdatePlan` compile the
binding's single policy through IG (multi-policy plans are refused, D3), check
that IG's matched-rule mapping equals the backend's provenance, stage the route
generation before `PublishCompiled`, and retry stale compilations a bounded
number of times. The binding's route scope (its registration's scope cookie) is
recorded before anything is staged. A publication whose outcome is unknown
stays pending with its staging (Resume republishes it, AbortPending discards
it). Verdict events are demultiplexed by the bound cgroup (so events between
the kernel commit and its receipt are delivered), must carry the registered
scope, and are translated from route generations to backend generations;
stopped bindings tombstone their (cgroup, scope), so a reused cgroup ID never
receives a retired binding's in-flight events. A first publication whose
outcome is unknown (`fullruntime.ErrSharedPublishUnknown`) carries the scope IG
minted for it; that scope is kept only so Stop tombstones it too (the latched
route's late events are dropped, not reported as unbound), and never
attributes an event. Unbound-cgroup reports are
rate-limited. Shared events must carry a nonzero `load_epoch` (a missing or
zero epoch is refused); consumers key an exec on `Verdict.LoadEpoch`,
`TaskCookie` and `ExecID` together, since task cookies restart on every load.
Only this engine opts its decoders into the D1 Audit fault on shared events
(`deny 1, mode 1, error 1` as a would-deny `operational_error`); a decoder
without that opt-in refuses a shared-event Audit fault. A non-shared Audit
fault (the base event ABI) still decodes as a would-deny
`operational_error`. A product
binding's `Check` passes only when the node is Ready and
`SharedBindingStatus.Protected` holds at the route generation the binding
committed (attached, published, not WithdrawPending, no refused adoption, no
fault); a qualification binding's `Check` always fails.
`ApplySharedNodeHealth` maps node Ready, the node's Degraded conditions and the
fail-closed, fact and verdict-loss witnesses into node conditions (Degraded
never makes Ready False, D2); a Ready product node keeps the controller's Ready
condition. The integration status writer applies it to every node status when
the shared engine is selected.

## Legacy API

`NewNative` / `Compile` remain a separate path-only, single-policy API with
immutable candidate replacement and dedicated compatibility tests. Actor/image/
filesystem/argv/role predicates and multiple policies are rejected there. The
public service never falls back to this API. Legacy events omit richer facts and
only attribute unambiguous decisive rules. Local fake-engine tests do not prove
BPF readiness or kernel enforcement.
