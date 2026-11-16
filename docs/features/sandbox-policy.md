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
 "sandboxPolicyMaxOwners": 2}
```

Enabling requires an explicit, trusted mutator image reference in `tracers.tar`,
compiled from the **same IG revision as the Go runtime owner**. Do not substitute a
trace gadget or reuse an older policy-map layout. The public dependency already
pins the published per-binding persistent-owner backend at
`87a796fe97803ec6788e985e6570efea46124fba`, as detailed below. The G020 shared
node engine is a separate, opt-in engine that enforces only on two exact
qualified kernel builds; see [Shared engine: supported kernels](#shared-engine-supported-kernels).
No mutator image is implicitly
downloaded, trusted or published by this change. IG treats an explicit local OCI target as pretrusted and skips its signature
verification. The archive must therefore be authenticated by the administrator
as part of the agent-image supply chain; the verification flag alone does not
authenticate it. Policy authors cannot choose the image/archive.

Enabling also requires explicit administrator-trusted `sandboxPolicyContainerdSocket`
and writable `sandboxPolicyControlRoot` paths. The socket and its parent must be
protected from workload substitution. The host root/proc mount must be a trusted
host mount, not a workload-supplied path. `sandboxPolicyMaxOwners` (1–2,
default 2: IG's legacy per-cgroup Owner hard cap per node, G009; larger values
are refused at configuration load) reserves aggregate capacity for persistent owners, including cleanup
pending owners. Each owner reserves 128 MiB of map payload capacity, one million
encoded instructions and bounded identity/epoch history; these ceilings are not
RSS or JIT memory measurements. Unsupported kernels, runtimes and images refuse
admission rather than falling back to the legacy backend.

The host-root (`/host`) volumeMount must use `mountPropagation: HostToContainer`
(checked on every lease); the chart sets it on `/run` too. Bind-volume provenance opens each bind
source through the host root and requires the same inode as the container
destination. Sources the host mounts after the agent starts, such as the pod
sandbox `/dev/shm` tmpfs and kubelet secret/projected tmpfs volumes (including
the default service-account token), are invisible through a host root with the
default `None` propagation, and every such bind is refused as an inode mismatch.
Each lease therefore requires the host-root mount to carry a `master:` or
`shared:` propagation tag in `/proc/self/mountinfo` and otherwise refuses with
a message naming the setting. Propagation is one-way: workload containers gain
nothing. It also means the agent sees whatever host-root processes mount later,
including a mount stacked over the containerd socket path. The host root is
already trusted (see the socket requirement above), so this adds no new trust.

Requires Kubernetes, BPF LSM with working attachment support, cgroup v2, and
host-visible procfs/cgroup discovery. Runtime container IDs, pod UID, PID, mount
namespace, cgroup path and cgroup inode must agree. Root cgroups and incomplete or
reused identities are refused. BPF verification or a kernel version string alone
does not establish these capabilities.

The host's PID 1 (through the host procfs) must be in the kernel's initial
cgroup namespace; cgroup membership is read there because a pod-confined agent
sees namespace-relative paths. Container root overlays must use the overlay
module defaults of AL2023 (`/sys/module/overlay/parameters`: `index`,
`xino_auto`, `redirect_dir`, `metacopy` and `nfs_export` N;
`redirect_always_follow` Y or N). These are checked before and after every root
observation, because mountinfo omits options equal to the current defaults.
Accepted overlay options are `lowerdir`, `upperdir`, `workdir`, `rw`,
`relatime`, `nosuid`, `nodev`, `noexec`, `seclabel`, `uuid=on`, `index=off`,
`xino=off`, `metacopy=off` and `redirect_dir=off|nofollow`; anything else,
including `metacopy=on`, is refused.

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

Each report carries `appliedGeneration`, the oldest policy generation still
installed on the node, counting container bindings and privilege pod cgroup
bindings. It stays on the last-good generation while a newer revision is
rejected, and is absent when no binding enforces the policy. `stale` is set only
when an installed binding lags the desired generation or its protection cannot be
confirmed: a failure that leaves the current generation enforced is `Ready=False`
with `stale: false`. At
startup the agent reads the host's active LSM list once. Every section enforces
through BPF LSM, so when `bpf` is missing every report says `tier: none`, and
every enabled policy reports `Ready=False` with reason `BPFLSMInactive`.

A privilege pod cgroup binding counts only where the witness counters confirm
it: the pod was bound before any of its containers existed, in the instance
that enforces now, and its slot has no tracking fault. "Its containers exist"
comes from the pod's API status and from the container collection (by pod UID
and by cgroup path); a container created after that snapshot is seen at the
next call. A pod whose containers already exist gets no pod binding; its
containers rely on their own bindings. A bound pod whose plan changes later
moves to its new slot, unconfirmed. While the instance is not ready, every pod
binding is unconfirmed.
A pod binding whose slot has a fault makes the policy report
`ProtectionUnconfirmed`. For a Strict slot a node tracking fault (a lost child
mark of a `CLONE_INTO_CGROUP` fork anywhere on the node) is a fault too; a new
instance clears it; node faults alone start a new instance at most every 10
minutes, because their cause may persist.

The privilege section reports Ready only on a qualified kernel. A kernel is
identified by its release (`uname -r`), its architecture (`uname -m`) and the
SHA-256 of its BTF (`/sys/kernel/btf/vmlinux`), so two builds with one release
differ. `sandboxPolicyQualifiedKernels` lists entries `release,arch,btf-sha256`;
unset or empty uses the built-in list, which holds only kernels whose kernel
test logs are posted (today AL2023 amd64 `6.12.113-138.209.amzn2023.x86_64` and
`6.18.56-125.164.amzn2023.x86_64`).
`["*"]` turns the gate off: a privilege policy can then be Ready, with the
reason `KernelGateDisabled`. On another kernel the section still enforces, but
every privilege policy reports `Ready=False` with reason
`PrivilegeKernelUnqualified`.

Pod cgroup bindings do not exempt OCI runtime helpers by default: a
createContainer or startContainer hook that runs inside the pod cgroup is
judged like the workload, so a Strict policy that denies what the hook does
fails the container start. The host operator can consent to the exemption with
`sandboxPolicyRuntimeHelperExemption: true`. Pod bindings then carry the
`RuntimeHelpers` flag, and each policy with such bindings reports the
`RuntimeHelperExemption` condition with the number of flagged pod bindings and
the execs the exemption left unjudged on the node (`ExemptExecs`; `Unknown`
when the counter cannot be read).

A privilege change commits in two phases: the privilege slot is prepared first
(this can replace the node instance and binds nothing), then exec commits, then
the privilege bind is a live map write. A failed prepare leaves both sections on
their last-good plan. Removing the privilege section withdraws it first: a
withdraw on an instance that is not ready stays pending and is retried, and exec
does not change meanwhile.

## Shared engine: supported kernels

The G020 shared node engine runs one node-wide IG collection for every binding
instead of one owner per binding. It is off by default. It is selected by
`sandboxPolicyEngine: "shared"` with a non-empty `sandboxPolicySharedImages`
map (below); the chart sets both from `nodeAgent.config.sandboxPolicy.sharedImages`.
The IG contract is in the IG `gadgets/enforce_exec/fullruntime/README.md`,
section "Shared engine: supported kernels", which this section follows.

### Supported kernel builds

The shared engine enforces only on the same kernel builds that were qualified:

| Release | vmlinux BTF sha256 | GNU build-id |
|---|---|---|
| `6.12.113-138.209.amzn2023.x86_64` | `0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82` | `1d135d67e6d0ea8f77d60a2984915eadd28a5fcf` |
| `6.18.56-125.164.amzn2023.x86_64` | `d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee` | `884ed4548406a1461ac5fb658c0dffdd87f1b3b2` |

These builds ship in these AMI releases (IDs from the qualification runs; IDs
differ per region, release names do not):

- plain AL2023 `al2023-ami-2023.12.20261026.1-kernel-6.12-x86_64`
  (`ami-0e8550404ae6ca4c6`) and
  `al2023-ami-2023.12.20261102.0-kernel-6.18-x86_64` (`ami-0516089d963059a51`):
  qualified with the qualification build (G011 pass 1). **Product
  admission and Ready on both pinned kernels are proven** (G011 pass 2, run g011p2-20261115t143731-5a41, 116 PASS / 0 FAIL).
- EKS-optimized `amazon-eks-node-al2023-x86_64-standard-1.35-v20261031`
  (`ami-0c50b8c0d6d72c152`, 6.12) and
  `amazon-eks-node-al2023-x86_64-standard-1.36-v20261031`
  (`ami-07ef7f0d9b6d0f123`, 6.18): the same kernel builds (the same BTF was
  recorded on both). **EKS product Ready is proven** (G011 pass 2b, run g011eks-20261115t163442-6da1, 120 PASS / 0 FAIL): the
  default build of this agent (one DaemonSet, the per-kernel image map) reached
  product Ready True ("Selected containers have active enforcement") on both
  AMIs. The EKS AMIs carry taint 12288 (out-of-tree or unsigned modules),
  which is allowed: only the livepatch bit is gated.

The build-ids were confirmed live from `/sys/kernel/notes` in G011 pass 2
(plain AMIs) and pass 2b (EKS AMIs).

Identity is the BTF sha256 **and** the GNU build-id (`/sys/kernel/notes`)
**and** the release (`uname -r`); the BTF alone does not identify a build. The
node also needs x86_64, `bpf` in the active LSM list, `ftrace_enabled=1` and no
livepatch; ftrace and livepatch are re-read at every node Ready. Ftrace is
detected, not guarded: root can set `kernel.ftrace_enabled=0` on a running
node (the kernel accepts it) and the shared node's Ready then reports
NotReady. In G011 pass 2, on both pinned kernels, a uid-1000 exec that a
Strict Deny policy denies (126) was allowed (0) once `ftrace_enabled=0` made
the shared Ready fail, and was denied again after ftrace was re-enabled.
Treat a node whose shared Ready fails as unprotected; this is an accepted,
detected limitation. IG also binds
the image to the build: its failure-frame symbols and the loaded eBPF object's
sha256 must be the pinned ones.

The agent selects the image at start, not lazily, with IG's
`fullruntime.SelectSharedProductImage`, which runs the full kernel gate. Every
other kernel is refused at agent start. No shared engine runs, nothing falls
back to the per-binding engine, every binding stays unprotected, and each
policy's node status reports Ready False with reason `SharedEngineUnavailable`
and the IG reason (it wraps `ErrSharedNativeUnavailable`).

### Why an allowlist

CO-RE relocates field offsets but cannot verify:

- hook semantics and ordering across the exec paths;
- the kprobe failure-frame symbols (`do_execveat_common.isra.N`, the handler);
- verifier acceptance of the 16-link, spin-lock object;
- exec-path behaviour changed by AL2023 backports under the same version
  string.

The costs are asymmetric. On an unproven kernel, Strict either fails closed
node-wide (an exec outage) or silently misses an exec path while reporting
Ready. A reported refusal is better than either.

### Support rule: pin the AMI

Support covers exactly the builds above; the rule is the build, not a calendar
date. Pin the AMI releases listed above: no in-place `dnf` kernel update, no
automatic node AMI upgrade, no livepatch. A node that moves to any other
kernel build, newer or not, is refused at agent start until that build is
qualified and pinned in a new IG release (and its image is added to the map
below). Support for a node ends when its operator moves it to another AMI or
kernel.

### The image map

`sandboxPolicySharedImages` maps a kernel BTF sha256 to the product image
qualified for that build:

```json
{"sandboxPolicyEngine": "shared",
 "sandboxPolicySharedImages": {
   "0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82": {
     "image": "<image name inside tracers.tar>",
     "profileFile": "/etc/sandbox-shared-profiles/0d7b...cd82.json",
     "manifestDigest": "sha256:<its amd64 image manifest digest>"}}}
```

- The key is the sha256 of `/sys/kernel/btf/vmlinux` on that build, in
  lowercase hex (`sha256sum /sys/kernel/btf/vmlinux`); use the values in the
  table above.
- `image` names the product image built for that kernel, inside the agent's
  `tracers.tar` archive (read-only; the same trust rules as
  `sandboxPolicyImage` above).
- `profileFile` is the `fullruntime.SharedProfile` JSON the image was built
  with (its exact geometry; unknown fields are refused).
- `manifestDigest` is the digest of the image manifest the agent loads: the
  `linux/amd64` manifest of the image index the `image` name resolves to (for
  example `oras manifest fetch --descriptor` on that platform, or the index's
  `manifests[].digest` for `amd64`). At start, and again before the node
  starts, the agent resolves `image` in `tracers.tar` the way IG does and
  refuses an image whose manifest digest differs, or an index with more than
  one `amd64` manifest or a manifest without a platform. The manifest
  content-addresses the config and the eBPF layer.
- `sandboxPolicySharedImageProcRoot` and `sandboxPolicySharedImageHostRoot`
  (default `/host/proc` and `/host`) locate the host procfs and root; the
  chart takes them as `sandboxPolicy.imageProcRoot` and `imageHostRoot`.
- `sandboxPolicyImage` stays required when the shared engine is selected, but
  the shared engine does not use it (it is the per-binding engine's image).

In the chart, set `nodeAgent.config.sandboxPolicy.sharedImages` (default
empty: the shared engine stays off). Quote the keys. Each entry takes `image`,
`manifestDigest` and the `profile` object; the chart renders the profiles into
the `<name>-sandbox-shared-profiles` ConfigMap, mounts it read-only at
`/etc/sandbox-shared-profiles` and sets `profileFile` to
`/etc/sandbox-shared-profiles/<btf>.json`. The chart refuses `sharedImages`
together with `sharedQualification`. A qualification build (tags
`sandbox_shared_qualification,enforce_exec_shared_qualification`, deployed with
`values-shared-qualification.yaml`; never Ready, and the only build with the
verdict-log receiver) refuses the map, and the default build refuses
`sandboxPolicySharedProfileFile` whatever the engine. Configuration errors (a malformed
key, a relative profile path, a digest that is not sha256) stop the agent at
start; a kernel without an entry, a refused kernel, a missing image, a manifest
mismatch or a bad profile do not, and are reported as above.

### Health

- A binding is reported protected only if the node is Ready **and** IG reports
  the binding protected at the route generation the agent committed
  (`SharedBindingStatus.Protected`): its receipts are attached, its route is
  published and not WithdrawPending, its generation is the committed one, no
  root-task adoption was refused and it has no fault.
- node-agent is a "report NotReady" host in the sense of IG's host contract:
  a Strict adoption refusal does not fail the container start. The binding
  stays unprotected and its policy is reported NotReady.
- Node Ready (`NodeEnforcer.Ready`) fails on startup or attach receipts, the
  reaper, the witnesses (credit at exit, exec capsule, birth park, facts), a
  fail-closed NotReady or Unknown window, a refused Strict namespace, and
  ftrace off or livepatch. Any of these makes every policy's Ready False with
  reason `SharedNodeNotReady`. Ready may be nil with zero bindings, but the node
  starts on the first binding; before that Ready is False
  (`SharedNodeNotStarted`). A failed node start is Ready False
  (`SharedNodeStartFailed`, with the error) and is retried after a backoff
  of 1 s doubling up to 1 min, not on every reconcile.
- A binding whose commit receipt was inconsistent (another route generation
  than compiled, a zero or mismatched scope) stays unprotected until a later
  clean commit, and the node reports Degraded `BindingProtocolFault`.
  The same policy revision is not republished, so to recover, change the
  policy (a new revision is published and committed) or restart the agent.
- Degraded (`NodeEnforcer.Degraded`, never NotReady on its own, D2): a
  fail-closed Degraded window (`FailClosedDegraded`), verdict event loss
  (`VerdictEventLoss`), the image ledger fault (`ImageLedger`), and a refused
  adoption, a revision report or the overlay layout (`SharedNodeDegraded`).
- A Ready node never raises Ready: the controller's own Ready condition (True
  only when every binding was confirmed) is kept.
- This health applies only to the status of active (not Off) policies with exec rules (an exec section or profile sources); for those, an existing Degraded condition is kept and the shared engine's reasons are merged into it, and other policies' Ready and Degraded are untouched. Condition reasons are cut to 128 characters (whole reasons, then `More`) and messages to 512, with `truncated` set.
- An active policy without exec rules still binds its containers to the shared engine (an empty exec policy is published) and skips the node Degraded overlay, but its Ready still requires the node to be Ready, through each binding's check.
- `AgentStopping` (any engine): on a graceful stop the agent writes Ready
  False with reason `AgentStopping` ("node-agent is stopping; enforcement is
  withdrawn until it restarts") for every active exec policy it reports,
  before it withdraws enforcement, and writes no status afterwards. The write
  is best-effort: shutdown waits for it at most 2.5 s, a failure is logged and
  shutdown continues; if a slow reconciliation delays it past that wait, it is
  still written (within its own 2.5 s) after that reconciliation's last
  write. With the shared engine, its Ready False reason can replace
  `AgentStopping` (`SharedNodeNotReady`, `SharedEngineUnavailable`,
  `SharedNodeNotStarted`, `SharedNodeStartFailed` or `QualificationOnly`);
  Ready is False either way. Active policies without exec rules keep their
  last report: they never enforced anything.

### Operational facts and what is unproven

- An agent crash or restart leaves enforcement **off until the agent is
  restarted**: the in-kernel state dies with the agent's BPF objects. A
  graceful stop writes Ready False (`AgentStopping`) before enforcement is
  withdrawn. Enforcement is off between agent processes during a restart: about 85 s (6.12) and 88 s (6.18) observed on EKS (G011 pass 2b; the new agent needed about 77-78 s to reach Ready). A graceful stop is reported by `AgentStopping`; a crash restart was not exercised. A crash or SIGKILL cannot write anything, so the last report
  (possibly Ready True) stays. The agent reports nominally every 5 s, but a
  pass that starts the node (up to `FullStartupTimeout`, 2 min) or waits on
  native operations (`FullOperationTimeout`, 5 s each) delays the next
  report: consumers should treat a report whose `lastReported` is older than
  30 s as NotReady. A first node start can exceed even that, so the policy is
  then shown NotReady or stale until the start completes. The restarted agent
  reports Ready True only after its bindings are protected again (node Ready
  and each binding confirmed).
- **Unproven:** SELinux enforcing (the qualification ran Permissive); lockdown
  modes other than none; other BPF users beyond the synthetic coexistence
  tests; unsigned or out-of-tree kernel modules beyond the EKS AMIs' taint
  12288 (allowed); arm64; any other AMI.
- Limits of the G011 evidence: in-pod reads cover verdicts and self-status
  only, facts are shown by outcome, and the default build has no fact counters.
  The restart ordering of Ready versus re-protection is ordered by code but not
  decidable from the evidence at 1 s resolution. Selection of the per-kernel image map entry is evidenced only through the wrong-digest negative; the positive run shows the selected entry works, not which entry was chosen.
- Argv predicates are refused (D1). The AT_EXECVE_CHECK and RETIRING residuals
  (D3/D4) and the migration-out residual apply (see the IG README). One policy
  per binding: multi-policy plans are refused (D3).
- IG re-resolves the image name in the same read-only `tracers.tar`; the agent
  binds the manifest digest and IG binds the loaded object's sha256 to the
  pinned objects.

### Future work (not implemented)

1. **Startup self-test on an unlisted kernel:** load, probe execs, check hook
   firing and ordering, then enable.
   - Pro: broad coverage.
   - Cons: proves only the exercised paths (races, binfmt_misc, ptrace and rare
     paths stay unproven); needs a test cgroup on production nodes; adds
     startup latency; a false pass is a silent bypass.
2. **Audit-first, promoted to Strict after a clean period.**
   - Pro: no outage risk; reuses the fail-closed witness thresholds.
   - Cons: missed hooks look clean; the clean period is arbitrary; no
     protection meanwhile; promotion needs an operator.
3. **Targeted BTF matching** of the functions and types the object depends on,
   instead of the whole-vmlinux hash.
   - Pro: survives unrelated backports.
   - Cons: types do not prove semantics or call order; the dependency set must
     be complete and maintained; a gap is a silent bypass.
4. **Bulk kernel-family qualification** (stock-kernel matrix,
   kubescape/inspektor-gadget#27).
   - Pro: today's proof strength.
   - Cons: about an hour of EC2 per kernel; needs a pipeline that tracks
     vendor updates; the allowlist lags new AMIs.

The likely combination is (4) for support claims, with (3) and (1) only as a
pre-check, never as a Ready claim.

### Follow-ups

- node-agent does not yet consume IG's `SharedNodeConfig.AttachState` or
  `ErrSharedBindingCapacity`. Both would give more specific NotReady reasons.
  Today the node stays unstarted (Ready False) during IG's bounded attach
  retry, and a capacity refusal surfaces as a generic Bind error.

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

A live container can appear in runtime discovery before kubelet reports it
Running (the usual order when a container starts). Each refresh runs the policy
selectors on such a container. It uses the API pod's labels, and IG's own
Kubernetes metadata (pod labels, container name), and treats the container as
selected if either view selects it. Selection that cannot be evaluated (no IG
labels and no pod UID, or an unknown namespace) counts as selected. A selected
container that is not yet correlated is binding pending. Pending is non-fatal:
the snapshot still binds every correlated container (new ones are installed,
none is withdrawn because of the pending one), and every policy on the node
reports Ready False with reason `BindingPending`, for example `1 live
container(s) selected by policies on this node are not yet bound; other
selected containers are bound`. `error` also carries the count. The count is
node-wide and the condition appears on every policy on the node, including
policies that do not select the pending container. If another failure applies
to a policy, its reason is kept and the pending count is appended to the
message. For `CleanupPending`, `WithdrawalCleanupPending` and
`ProtectionUnconfirmed`, whose messages are fixed, the count appears in `error`
only. Ready True is never reported while a pending container exists; there is
no grace period.

Expect a brief `BindingPending` on each selected container start: the refresh
triggered by the container event usually lands between container creation and
kubelet reporting it Running. It clears on the next refresh after kubelet
reports Running (another event or the 5 s pass). A container that stays live
but never reaches Running (for example a hung exec PostStart hook) keeps every
policy on the node at `BindingPending` indefinitely, but does not block the
binding of any other container.

A live container is not pending when:

- it has no Kubernetes metadata (host or non-Kubernetes discovery);
- kubelet already reports its runtime ID Running (API selection decides);
- it is terminating: kubelet reports its runtime ID exited (current or last
  termination state), its pod has a deletion timestamp or is Succeeded/Failed,
  or its pod UID is absent from the node pod list (discovery is read before the
  pod list, so the pod was deleted). A terminating container therefore causes no
  NotReady flapping.

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
matching IG owner documentation and exact BTF admission gate, and for the
shared engine [Shared engine: supported kernels](#shared-engine-supported-kernels).

ContainerProfile import currently requires a completed profile with full
coverage, an unambiguous selected container and literal paths. Exact argv-length,
argument-wildcard and environment constraints cannot be represented faithfully by
the CRD exec vocabulary and are refused rather than broadened.

## Role-entry authoring

Treat `setRole` on an allow rule as an **authorization grant**, not just an event
label. An omitted or empty actor, or a wildcard-only actor constraint, can grant
the role broadly to matching successful execs. The current compiler accepts
such broad grants; an empty actor object is not a mitigation or a validation
workaround.

Constrain entry using a meaningful trusted actor, the intended target and the
policy-local authorization boundary. Review how the launcher's trusted role
history was established; missing history is not authority, and an executable
path or image origin alone does not establish trust in its inputs. A constrained
native Go IR example and its assumptions are documented in IG's
[role-entry authoring and isolation guidance](https://github.com/kubescape/inspektor-gadget/blob/8224dd6e694ad43b83ca1dc85de8d2b954d5f98e/gadgets/enforce_exec/fullruntime/README.md#role-entry-authoring-and-isolation).
That example is not CRD YAML or a complete deployment policy.

Roles are **not hostile-code isolation boundaries**. Untrusted code may invoke a
trusted launcher as a confused deputy or delegate work through IPC, shared files
or services. Review that reachable authority, including pod-shared resources,
rather than assuming a role label prevents delegation.

## Runtime evidence input limits

The containerd evidence path refuses oversized metadata before its relevant
content read or JSON decode. These are supported-input limits, not a total heap,
process-memory or IG `CompileBytes` bound:

- Raw container and sandbox OCI specs: **1 MiB each** before JSON decoding;
  existing encoded-spec size checks still apply. CRI extensions retain their
  existing **1 MiB each** predecode limit.
- Image indexes, manifests and configs: **16 MiB per blob and 16 MiB aggregate**
  per evidence observation. The actual content-store reader size is checked,
  not merely the descriptor's claimed size. Repeated reads and inspected inline
  descriptor data count again; an invalid inline attempt followed by a store
  read charges both. Admitted failed reads are not refunded.
- Descriptor traversal retains containerd's **10,000 references**, including
  duplicates. Existing limits of **128 image diff IDs** and **128 snapshot
  ancestors** remain in force.

The raw-spec and streamed/aggregate metadata ceilings are stricter input-domain
restrictions: whitespace-heavy specs or large multi-platform metadata may now be
refused even if their eventual selected representation was previously accepted.
Nested inline data is allocated while decoding its size-admitted parent; its
later byte check does not claim to prevent that earlier allocation. Decoder
copies, RPC buffers and provider-owned asynchronous state are not covered by a
16 MiB heap claim.

Excess is unsupported evidence and fails closed. On re-attestation it follows the
existing sticky evidence-failure path, not the retryable transport-unavailable
exception. This does not remove or weaken any image, mount, identity or native
readiness check, and does not expand the supported runtime/kernel matrix.

## Public event hooks

Register receivers in `ThirdPartyTracers.ThirdPartyEventReceivers` under
`utils.ExecAuthorizationEventType`. The public `VerdictExporter` accepts
`EnrichedEventReceiver`, `EventReceiver`, or `sandboxpolicy.VerdictReceiver`.
Optional process-tree enrichment uses the existing `TaskBasedEnricher` interface.
Private OTel export is intentionally not implemented here.

`ExecAuthorizationEventType` (`execAuthorization`) is an internal receiver-dispatch
key, not an OTEL event name. Construct snapshots with `NewExecVerdictEvent`.
An exporter may reuse the ordinary exec wire family with an explicit authorization
phase, but that mapping must not route authorization through ordinary exec
observation processing or imply syscall success.

`ExecVerdictEvent` implements `EnrichEvent`, **not** `ExecEvent`: an LSM denial is not
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

### Verdict telemetry metrics

Every 15 s the service exports its verdict counters through the agent's
metrics manager (OTel; with `OTEL_METRICS_EXPORTER=prometheus` each `.` becomes
`_`, so `node_agent.sandbox_policy.decode_errors.total` is scraped as
`node_agent_sandbox_policy_decode_errors_total`). They are observability only:
enforcement, fail-closed behavior and Ready/Degraded never read them.

| Metric | Labels | Meaning |
|---|---|---|
| `node_agent.sandbox_policy.exporter.events.total` | `result`: `enqueued`, `delivered`, `dropped`, `receiver_error`, `enrichment_error` | `Service.ExporterStats()`. `dropped` counts a full queue, a cancelled or stopped exporter, and every verdict with no receiver registered under `ExecAuthorizationEventType`. `delivered` counts receiver invocations, not kernel decisions. |
| `node_agent.sandbox_policy.kernel.events.total` | `result`: `submitted`, `lost`, `observation_error` | Kernel verdict-ring counters: the shared node's counters with the shared engine, else `Service.KernelEventStats()` owned plus retired totals. `lost` is a failed ring reservation. |
| `node_agent.sandbox_policy.decode_errors.total` | none | Verdict events dropped because they could not be read from the datasource or decoded against their generation's catalogue (`igbackend.ErrVerdictDecode`). Each one is also reported to `OnError`. |
| `node_agent.sandbox_policy.kernel.stats_complete` | none | 1 when every kernel counter was readable; 0 when some were not (an unreadable shared-node counter, or an unavailable owned or retired instance), so the kernel totals are a lower bound, or the kernel read was cut short (totals unknown for that pass). With the shared engine and no node started it is 1 (no kernel events exist). |

The counters are exported as growth above each counter's highest seen value:
a total that falls (an unreadable instance, a restarted shared node) adds
nothing, and only its growth past that value is counted later. With the
per-binding engine, the wait for the binding records' locks is bounded to 1 s
(best effort: a shared-engine `Health()` read and a per-instance counter read
are not interrupted); a read cut short exports no kernel counters for that pass
and sets `stats_complete` to 0. Every 15 s the counter pass briefly holds the
binding registry and record locks, so a binding change can wait for one pass:
enforcement is only delayed, never weakened.

When `dropped`, `receiver_error`, `enrichment_error`, decode errors, `lost` or
`observation_error` grow, the service reports one `OnError` diagnostic
("sandbox verdict telemetry loss ...") with the growth since the last one, at
most once a minute. The kernel counters do not cover early native owner/gate
refusals (see below).

### Adding a second enforcement gadget

`ExecVerdictEvent` and the current `Verdict` payload are exec-specific; their
existing names do not define a generic contract for open, connect or syscall
authorization. When adding the second gadget:

1. Define a distinct operation-specific event and authorization dispatch key.
   Keep exec target/argv, open path/flags, connect destination and syscall facts
   in their own typed payloads, rather than adding unrelated optional fields to
   `ExecVerdictEvent` or making authorization implement observation interfaces.
2. Compare the two concrete payloads and extract only genuinely shared decision,
   mode, policy/revision/match, completeness and captured-binding metadata.
   Preserve absence, immutable snapshots and identity validation. Do not assume
   exec's binding requirements or provenance fields apply unchanged to another
   hook; validate that contract before sharing it. No shared abstraction is added
   preemptively by this exec-only implementation.
3. Preserve separate authorization dispatch through the public receiver hooks.
   At the exporter boundary, extend the corresponding existing operation's wire
   family with explicit authorization versus observation semantics and policy
   metadata. Update its backend contract/tests; do not carry exec-specific
   attribute names into another operation or silently imply operation success.
4. Reuse bounded telemetry/loss handling only where semantics match. Reporting
   failures must not alter enforcement decisions. Test each operation's unknown
   fields, deny/audit/allow cases and receiver isolation, plus mixed-operation
   dispatch and snapshot ownership for any shared metadata extracted.
5. Treat cross-producer occurrence correlation as a separate contract. A common
   metadata struct or wire family does not make two records the same attempt;
   do not suppress observations using PID/path/time heuristics.

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
`6b8b24afaf6f2fd9eeb1bcaa9f7a52f4f11e9ea1`, and review fixes through
`c2aa29f9ca0d4dfa9300ffb9a7461a464b60f998`, in IG PR #15. The signed-off merge
`90147104198e91083298a132854d9de77d98091c` also incorporates IG main through #16,
preserving its ordinary-symbol streaming fix. Follow-up review fixes through
`f9467312a221885cf144aa3289df3b0260af25e9` reject noncanonical exec prefixes
and make attachment initialization cancellable. The reviewed revision
`87a796fe97803ec6788e985e6570efea46124fba` additionally admits only the exact
Kubernetes-capable kernel BTF proved by the full predicate, persistent OCI and
authenticated CRI matrix, while retaining the original artifact. Private
Kubernetes/OTLP integration remains separate and pending. Node-agent pins that
exact public pseudo-version and passes targeted tests, race checks, vet and binary
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

## Workload seccomp contract

Trusted image evidence requires a stable container root. Periodic root checks
cannot see a chroot or namespace change between observations, so every admitted
workload must run under an OCI seccomp profile with exactly this shape. Anything
else is refused (`validateRootSeccomp`):

- `defaultAction` `SCMP_ACT_ALLOW`, `architectures` exactly `["SCMP_ARCH_X86_64"]`
  (amd64 only). The i386 and x32 ABIs hit the bad-arch action and are killed.
  This assumes runc leaves libseccomp's default bad-arch action (KILL) in place,
  as runc 1.3.x does; it cannot be expressed or checked in the OCI profile.
- `chroot`, `pivot_root`, `unshare`, `setns`: unconditional
  `SCMP_ACT_ERRNO` with `errnoRet` 1 (EPERM), no `args`.
- `clone3`: unconditional `SCMP_ACT_ERRNO` with `errnoRet` 38 (ENOSYS), no
  `args`. EPERM is refused. Its flags are in a user-memory struct that seccomp
  cannot inspect, so it is blocked outright. It must be ENOSYS because glibc
  (2.34 and later) `pthread_create` falls back to `clone(2)` only
  on ENOSYS. With EPERM, thread creation fails and most real workloads
  (cgo-linked Go, Java, threaded C) break. Docker's and containerd's default profiles use ENOSYS for
  the same reason.
- `clone`: two rules, each alone in its own entry, `SCMP_ACT_ERRNO` with
  `errnoRet` 1 and one arg `{"index":0,"op":"SCMP_CMP_MASKED_EQ"}`, where
  `value`=`valueTwo`=`CLONE_NEWUSER` (268435456) in one rule and `CLONE_NEWNS`
  (131072) in the other. The `clone(2)` fallback still hits these rules.

```json
{"defaultAction":"SCMP_ACT_ALLOW","architectures":["SCMP_ARCH_X86_64"],"syscalls":[
 {"names":["chroot","pivot_root","unshare","setns"],"action":"SCMP_ACT_ERRNO","errnoRet":1},
 {"names":["clone3"],"action":"SCMP_ACT_ERRNO","errnoRet":38},
 {"names":["clone"],"action":"SCMP_ACT_ERRNO","errnoRet":1,"args":[{"index":0,"value":268435456,"valueTwo":268435456,"op":"SCMP_CMP_MASKED_EQ"}]},
 {"names":["clone"],"action":"SCMP_ACT_ERRNO","errnoRet":1,"args":[{"index":0,"value":131072,"valueTwo":131072,"op":"SCMP_CMP_MASKED_EQ"}]}]}
```

The profile is one half of the barrier. A user namespace can only be created by
`clone`, `clone3` or `unshare`, and it is the only unprivileged way to gain
CAP_SYS_ADMIN. `mount`, the new mount API (`fsopen`, `fsmount`, `open_tree`,
`move_mount`, `mount_setattr`), `pivot_root` and new mount namespaces also need
CAP_SYS_ADMIN, and `chroot` needs CAP_SYS_CHROOT. The OCI spec and live
`/proc/<pid>/status` checks refuse both capabilities, so those calls fail even
though the profile allows them.

runc must link libseccomp 2.4.2 or later, the first release whose syscall table
includes `clone3`. runc silently ignores syscall names libseccomp does not know,
so an older libseccomp drops the `clone3` rule and leaves `clone3` allowed.

The barrier covers changes of the root and namespaces only. It does not cover
file descriptors supplied from outside, such as a directory fd received over
`SCM_RIGHTS` or leaked by the runtime, which can reach paths outside the root
without changing it.

`TestRootSeccompKernelThreadsWorkAndNamespacesDenied` loads this profile into a
real kernel in a child that is root with full capabilities in its own user and
mount namespaces. A no-filter control first shows that none of the denied calls
returns EPERM there. With the filter, Go and libc threads work and every
namespace and root change returns EPERM.

## Pinned CRI kernel validation

The live kernel fixture is excluded from ordinary test builds. On an approved,
isolated Linux qualification host, its explicit invocation is:

```sh
IG_FULL_BACKEND_KERNEL_TEST=1 go test -count=1 -tags=sandboxpolicy_kernel \
  ./pkg/sandboxpolicy/igbackend -run '^TestFullBackendContainerdKernel$'
```

**The build tag itself admits kernel-related dependency initialization, including
BPF map creation attempts, even when the opt-in environment variable is unset.**
Do not use the tag for ordinary unit tests or run the tagged binary outside the
approved kernel-qualification procedure. Setting the environment variable without
the tag fails explicitly rather than silently passing with no matching test.
The pure `TestFullBackendKernelFixturePlan` remains in ordinary Linux test builds.

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
