# SandboxPolicy execution enforcement (experimental)

The public service selects the persistent full-exec backend, with no path-only
fallback. Controller/watch/status behavior has client-backed regression tests;
node-agent's native backend has isolated real containerd/CRI kernel proof on the
explicitly pinned amd64 environment below. This is not generic runtime/kernel
compatibility or an API-server/kubelet deployment proof. Private OTel export is
out of scope. The IG dependency remains merge-gated until PR #15 is merged.

## Configuration and prerequisites

Disabled by default:

```json
{"sandboxPolicyEnabled": false, "sandboxPolicyImage": "",
 "sandboxPolicyContainerdSocket": "", "sandboxPolicyControlRoot": "",
 "sandboxPolicyMaxOwners": 4}
```

Enabling requires an explicit, trusted mutator image reference in `tracers.tar`,
compiled from the **same IG revision as the Go runtime owner**. Do not substitute a
trace gadget or reuse an older policy-map layout. The public dependency currently
pins the prototype revision; publishing/re-pinning the expanded backend remains
outstanding. No mutator image is implicitly downloaded, trusted or published by
this change. IG treats an explicit local OCI target as pretrusted and skips its signature
verification. The archive must therefore be authenticated by the administrator
as part of the agent-image supply chain; the verification flag alone does not
authenticate it. Policy authors cannot choose the image/archive.

Enabling also requires explicit administrator-trusted `sandboxPolicyContainerdSocket`
and writable `sandboxPolicyControlRoot` paths. The socket and its parent must be
protected from workload substitution. The host root/proc mount must be a trusted
host mount, not a workload-supplied path. `sandboxPolicyMaxOwners` (1–1024,
default 4) reserves aggregate capacity for persistent owners, including cleanup
pending owners. Each owner reserves 128 MiB of map payload capacity, one million
encoded instructions and bounded identity/epoch history; these ceilings are not
RSS or JIT memory measurements. Unsupported kernels, runtimes and images refuse
admission rather than falling back to the legacy backend.

Requires Kubernetes, BPF LSM with working attachment support, cgroup v2, and
host-visible procfs/cgroup discovery. Runtime container IDs, pod UID, PID, mount
namespace, cgroup path and cgroup inode must agree. Root cgroups and incomplete or
reused identities are refused. BPF verification or a kernel version string alone
does not establish these capabilities.

Enforcement is independent of runtime-detection/application-profile switches.
There are **no inferred helper, host-mount-namespace or agent exemptions**. Strict
cgroup scope can block container-runtime helpers (`kubectl exec`, probes and
lifecycle helpers), including a helper that shares the target cgroup. An entrant
without accepted birth lineage can quarantine the owner: subsequent revisions
remain NotReady/protection-unconfirmed, rather than silently adopting that helper
or resetting roles. Explicit withdrawal can still drain and detach safely; a new
policy revision alone does not redeem structural lineage faults. Roll out
only in an explicitly selected test workload before production use.

Install the four CRDs from storage's SandboxPolicy API first. The agent needs:

- `kubescape.io`: get/list/watch SandboxPolicy, ClusterSandboxPolicy and
  SandboxPolicyClasses; get/create SandboxPolicyNodeStatus and update its
  `status` subresource.
- Core API: get the node UID; list pods on the node and namespaces for selectors.
- Storage API: get referenced ContainerProfiles read-only.

This change does not grant chart RBAC, change a chart version or store policy in
SQLite/files. Kubernetes owns the CRD objects. Per-policy/node status resources
are output; the agent does not write parent aggregate status.

## Reconciliation and failure behavior

Configuration watch events are **refresh hints**, not trusted queued payloads.
Each refresh reads an authoritative all-resource snapshot. This prevents an old
queued update from resurrecting a deleted/recreated policy. Container discovery
is subscribed before the initial runtime snapshot. A five-second recovery pass
also refreshes pod/namespace labels and referenced profiles, repairs watch gaps,
retries cleanup and reports status heartbeats.

Failed configuration lists keep a persistent NotReady barrier until a complete
relist succeeds. They do not authorize new bindings or removal of retained
last-good plans. Failed runtime snapshots also retain the previous authoritative
snapshot, report NotReady and are not interpreted as an empty container list. Discovery requirements are
policy-aware: an unselected, observer-filtered container does not block unrelated
bindings. An explicitly selected filtered container with unavailable identity is
NotReady; it is not exempted.

The first policy is activated only after native startup acknowledges all operators
and exact-identity checks pass. Subsequent revisions swap frozen program data in
the same owner; they do not restart maps, links or committed role state. Publication
closes exec admission and drains transactions, so concurrent exec attempts can
fail during this bounded maintenance window. A drain timeout retains the old
program and reports NotReady. Existing-owner publication, re-attestation and stop
operations have a five-second bound; first admission allows two minutes for the
bounded image-index walk and native load. Earlier caller deadlines still apply. Successful policy UID epochs survive revisions and
removal/re-addition within the same owner lifetime.
Precommit failure retains last-good enforcement **only when its live lease and
native readiness can still be confirmed**. Unchanged and retained plans are
re-attested; uncertain protection reports NotReady and is excluded from confirmed
active counts, rather than being described as healthy last-good enforcement.
Postcommit cleanup failure
records the actual new revision and reports NotReady. Cleanup retries do not
restart the new generation. Withdrawal records removal separately from cleanup;
replacement waits until conflicting cleanup finishes. Shutdown is retryable and
does not release the runtime before owned cleanup succeeds.

The full backend retains at most 1,024 owned identities, further constrained by
the explicit shared owner budget. Per owner the compiler bounds eight policies,
256 rules, 1,024 patterns, 256 predicate values and 16,384 IR entries. Paths may
contain at most 255 encoded bytes; argv capture is bounded to 64 arguments and
4,096 bytes. Oversized or unrepresentable candidates are rejected as a whole.
The supported runtime/kernel matrix remains deliberately narrow; see the
matching IG owner documentation and exact BTF admission gate.

ContainerProfile import currently requires a completed profile with full
coverage, an unambiguous selected container and literal paths. Exact argv-length,
argument-wildcard and environment constraints cannot be represented faithfully by
the CRD exec vocabulary and are refused rather than broadened.

## Public event hooks

Register receivers in `ThirdPartyTracers.ThirdPartyEventReceivers` under
`utils.SandboxExecVerdictEventType`. The public `VerdictExporter` accepts
`EnrichedEventReceiver`, `EventReceiver`, or `sandboxpolicy.VerdictReceiver`.
Optional process-tree enrichment uses the existing `TaskBasedEnricher` interface.
Private OTel export is intentionally not implemented here.

`VerdictEvent` implements `EnrichEvent`, **not** `ExecEvent`: an LSM denial is not
process creation. The payload preserves policy/revision, verdict, effective mode,
`WouldDeny`, and available rule/origin metadata. Unknown argv, UID, image origin
and actor path remain absent for legacy events. Legacy time is receipt time.
Exact binding correlation rejects stale pod/PID/mount-namespace metadata. An
ambiguous matching rule does not receive invented single-rule provenance.

Telemetry is bounded and best effort: a 1,024-entry service queue, explicit drop,
receiver-error and enrichment-error counters, exposed by `Service.ExporterStats()`. Slow/failing receivers cannot alter
kernel decisions. Void third-party receiver calls must return promptly; cancellation
cannot forcibly interrupt arbitrary user callbacks. Events are independent of
trace_exec's successful-exec filters and do not mutate the process tree as an exec.

## Verification boundary

Unit/race tests cover selection, reload bookkeeping, import refusal, status,
identity checks, queued-event ordering and public hook delivery. These are not
proof of kernel capabilities. Isolated IG tests have passed on Linux
7.0.0-31-generic x86_64 with BPF LSM enabled, including the 128th path, mixed modes,
strict scope, replacement/churn and reporting saturation; three repeat runs also
passed. They prove the expanded **legacy** backend, not the outstanding full
predicate integration. No arm64 or general-kernel support is claimed.

The separate advanced IG image has also passed isolated tests on a pinned custom
x86_64 kernel for staged argv from the new exec mm, actor/ancestor paths, effective
UID, stdin pipe facts, and overlay backing membership. Its native runtime tests
cover immutable-map admission and rollback. Supplied image-membership indexes in
those tests are **not proof of trusted container image discovery**. A separate
role-lifecycle spike proves fork/vfork inheritance, successful-exec-only commits,
script retries, nonleader exec and cleanup, not production role bootstrap or
revision publication.

Separate filesystem fixtures now prove tmpfs, deleted, overlay and authoritative
memfd classification, including an actual hugetlb-memfd exec denial. Untracked
pre-existing memfd remains unknown; a known positive filesystem alternative can
still match an OR list. Allocation exhaustion does not deny unrelated file
creation. The combined production image passed all 29 current live-exec cases, including
six filesystem cases; tracker attachment is probed before binding admission.

The persistent owner is connected through the public native backend, and the
pinned CRI proof below exercises its trusted image admission and live reload.
This remains a deliberately constrained environment, not broad distribution,
compiler or runtime compatibility. Refusal or isolated component tests alone are
not sufficient completion evidence.

The expanded IG revision is published as signed-off commit
`fe1de461890489288685634d12821f976b16d0a6`, followed by the lint-only commit
`6b8b24afaf6f2fd9eeb1bcaa9f7a52f4f11e9ea1`, in IG PR #15. Node-agent pins the latter exact
public pseudo-version and passes targeted tests, race checks, vet and binary
compilation with `GOWORK=off`. The repository's merge guard intentionally blocks
this stacked dependency until IG #15 merges; re-pin to its merged main revision
before merging the consumer change. Do not bypass that guard.

The native backend subscribes the advanced generation-specific event decoder.
Its `PolicySet` records the applied policies, and `Matches` records only
kernel-reported matching rules. Ambiguous multi-policy decisions do not invent a
single rule or policy attribution. `MatchesComplete=false` marks partial results
on operational faults. `Revision` remains the aggregate plan revision; policy
revisions are explicit in `PolicySet` and `Matches`. Fields absent from the kernel
event remain absent, including argv, UID and actor/image facts. Export queues and
receiver copies isolate the added slices from producer/receiver mutation.

## Pinned CRI kernel validation

The isolated combined fixture uses real containerd 1.7.30 / runc 1.3.4 CRI
RunPodSandbox/CreateContainer/StartContainer, not forged ctr metadata. It retains
the generated hosts, hostname, resolv.conf, sandbox shared-memory bind and
read-only cgroup mount. The host-network fixture has private PID/mount namespaces;
no Kubernetes API server or kubelet is involved in this kernel fixture. Controller
selection/status/watch behavior has separate fake-client tests.

`TestFullBackendContainerdKernel` exercises thirteen real paths under default
deny, full compound exec predicates, enforce/audit decisions, inherited roles,
same-owner reload, unchanged-plan checks, the full 256-rule/bit-255 boundary,
safe 257-rule rejection, public
verdict provenance and withdrawal. The matching test-kernel BTF is admitted
explicitly; this is not generic kernel, arm64 or containerd 2.x compatibility.

CRI shared-memory admission authenticates sandbox metadata and its runtime-owned
OCI spec, then compares actual source/destination inode/device and whole TMPFS
mount roots. The protected host source retains nosuid/nodev/noexec. Some runc
binds drop these flags on the application mount. That case requires **all five
capability sets empty in both OCI and live proc status, no-new-privileges in both,
and exactly the canonical restrictive OCI device-policy baseline with no authored
allows**. Trusted runc still permits OCI default safe devices; this is not a
literal deny-every-device claim. The bound init was kernel-tested to receive
EPERM opening unregistered char and block nodes created by the host in shared
memory, with mode 0666 and nonblocking read-only opens. No device data was read or
written. Ordinary TMPFS execution is enforced by the gadget, not assumed impossible.

Read-only cgroup mounts must be actual cgroup v2 with readonly/nosuid/nodev/noexec
properties. Other mounts, capabilities, device-policy variants or runtime layouts
are refused, not exempted. Shared-memory metadata churn can invalidate the bounded
double-scan evidence; this conservative stable-snapshot boundary is not proof for
arbitrary active-IPC workloads. Runtime helpers remain subject to strict scope.

The persistent-owner BPF object used for final isolated proof was compiled with
Clang 21.1.8 against the exact admitted kernel BTF. Clang 19 produced a
verifier-rejected owner object in this experiment; compilation alone is not a
compatibility guarantee. The default upstream builder is not evidence for this
experimental profile—use an explicitly matching, tested compiler/artifact.

`Service.KernelEventStats(ctx)` exposes owned and retired kernel submitted,
ring-reservation-loss and observation-error counters. Retired totals survive
withdrawal; unavailable-instance counts and returned errors must be checked
before interpreting zero loss. These are separate from userspace
`ExporterStats()`. Early native owner/gate refusals can occur before verdict
emission and are not counted as ring loss, so neither API promises complete
coverage of every operational denial.

Unreliable container snapshots use nonpublishing `Attest` for retained plans,
never `Replace`/`Resume`. Unsupported attestation reports protection unconfirmed.
Configuration-list failures freeze policy mutation and suppress confirmed-active
claims. Superseded uncommitted candidates must abort before another revision is
considered; already committed revisions cannot be rolled back.
