# Persistent execution-policy backend

The public service now uses `NewFull` with `NewNativeFullEngine` and
`NewContainerdFullSource`. The legacy `NewNative` / path-only converter remains
for historical tests, but is not a fallback for unsupported full policies.

`FullBackend` installs immutable generation provenance before native startup or
publication. First activation follows successful manager startup. Reload uses
`Owner.Update` / `Resume` on the same maps and links, retaining successful policy
UID epochs. Kernel commit is irreversible even if reopening/finalization fails;
reconciliation resumes that generation rather than rolling it back. Whole-exec
gate closure can disrupt concurrent execs. Unsupported inputs are refused.

One administrator-configured aggregate budget bounds all native owners. Exact
cgroups stay exclusively reserved until actual detach and release. Startup
failures retain partial owners and untransferred leases. Stop must complete
`BeforeStop` before manager cancellation, join real teardown, then call
`ReleaseAfterDetach`; failed cleanup remains owned and retryable. The trusted
containerd client closes only after every lease has been consumed.

The combined lease pins the exact proc allocation, cgroup, workload mount
namespace, initial-host PID/mount namespaces, stable root and complete lower
image inode index. It authenticates containerd task/image/CRI metadata, never
policy annotations. The protected socket and administrator host mounts are
trusted deployment inputs, not proven authentic merely by their path names.
The supported root/seccomp/capability and immutable overlay constraints apply
even when the current revision has no image predicate, because later revisions
reuse the same owner and origin index. A changed image/root invalidates that
owner, not an in-place index refresh. No inferred helper exemptions exist.

`FullVerdictCatalog` keeps at most 16 generation-specific decoders, including
active and staged provenance. Evicted/unknown generations are dropped rather
than attributed to a newer plan. Full verdicts use the kernel's typed four-word
match bitmap, with explicit incomplete matches for operational failures. UID,
argv, actor and image facts remain absent when the event does not supply them.
Exporter failures do not change kernel decisions.

## Verification boundary

Compiler, catalogue, transaction and lifecycle unit/race tests do not prove the
combined node-agent native path. The matching IG owner has isolated real-kernel
native OCI proof, and constrained containerd image discovery has separate proof.
The combined native/containerd1.7.30/runc1.3.4 CRI fixture now passes on the
pinned amd64 kernel, including generated managed files, shared memory, readonly
cgroup2, 13 paths, same-owner reload and actual public events. It does not run a
kubelet/API server or establish generic runtime/kernel compatibility. The exact supported kernel BTF gate is intentionally
narrow. Private OTel implementation is outside this public change.

The expanded IG revision is published and pinned at
`v0.0.0-20261027133411-87a796fe9780`; standalone node-agent targeted tests, race
checks, vet and binary builds pass without a development workspace. This revision
also includes IG main through #16, preserving the ordinary-symbol streaming fix,
and the individually proved Kubernetes-capable exact BTF artifact. Its isolated
upstream predicate/persistent OCI/CRI proof does not replace the still-pending
private Kubernetes/OTLP integration proof.
The pin is still on PR #15 rather than main, so the repository merge guard correctly blocks
consumer merging until the upstream change is merged and re-pinned.
No chart version has changed. No image is implicitly downloaded or trusted: the
local OCI archive is privileged administrator-supplied code, and IG skips its
signature verification for explicit local targets.

## Shared node engine (G020, qualification only)

`sharedengine_qualification.go` (build tags `sandbox_shared_qualification` and
IG's `enforce_exec_shared_qualification`) implements `FullEngine` over one
node-wide IG shared collection, started lazily on the first binding. Start binds
the trusted cgroup/init/CRI container ID; Activate and `UpdatePlan` compile the
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
receives a retired binding's in-flight events. Unbound-cgroup reports are
rate-limited. Shared events must carry a nonzero `load_epoch` (a missing or
zero epoch is refused); consumers key an exec on `Verdict.LoadEpoch`,
`TaskCookie` and `ExecID` together, since task cookies restart on every load.
Only this engine opts its decoders into the D1 Audit fault (`deny 1, mode 1,
error 1` as a would-deny `operational_error`); the default build refuses it
whatever the event schema. `Check` always fails: the engine never reports Ready until
sign-off. `ApplySharedNodeHealth` maps fail-closed, fact and verdict-loss
witnesses into node conditions (loss is Degraded only, D2); the integration
status writer applies it to every node status in tagged builds. The default
build does not include it.

## Legacy API

`NewNative` / `Compile` remain a separate path-only, single-policy API with
immutable candidate replacement and dedicated compatibility tests. Actor/image/
filesystem/argv/role predicates and multiple policies are rejected there. The
public service never falls back to this API. Legacy events omit richer facts and
only attribute unambiguous decisive rules. Local fake-engine tests do not prove
BPF readiness or kernel enforcement.
