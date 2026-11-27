# SandboxPolicy execution enforcement (experimental)

The public service runs IG's shared CO-RE exec engine (the G020 shared node
engine) on every kernel IG's probe-based admission accepts, with no path-only
fallback and no other engine. The privilege, network and file sections use the
same admission. Controller/watch/status behavior has client-backed regression
tests. Admission is not a proof of hook ordering or verdict semantics on a
kernel no suite ran on (see
[What is and is not proved](#what-is-and-is-not-proved)). Private OTel export
is out of scope. The IG dependency remains merge-gated until PR #15 is merged.

## Configuration and prerequisites

Disabled by default:

```json
{"sandboxPolicyEnabled": false,
 "sandboxPolicyContainerdSocket": ""}
```

The exec engine runs the product image compiled into the agent (in
`tracers.tar`, built from the pinned IG revision); configuration never selects
an image. The G020 shared node engine runs on any x86_64 kernel with the bpf
LSM active, ftrace on, no livepatch and a readable identity, the same way on
every kernel; see
[Shared engine: supported kernels](#shared-engine-supported-kernels).
`sandboxPolicyImage`, `sandboxPolicyControlRoot` and `sandboxPolicyMaxOwners`
are legacy keys: they still load (so older configurations keep working) but
default builds ignore them, and a non-empty `sandboxPolicyImage` or
`sandboxPolicyControlRoot`, or a `sandboxPolicyMaxOwners` other than 2, is
reported once at start at Warning level. None is required. (A `sandbox_shared_qualification` build still
reads `sandboxPolicyImage` as its shared candidate image.)
No image is implicitly
downloaded, trusted or published by this change. IG treats an explicit local OCI target as pretrusted and skips its signature
verification. The archive must therefore be authenticated by the administrator
as part of the agent-image supply chain; the verification flag alone does not
authenticate it. Policy authors cannot choose the image/archive.

Enabling also requires an explicit administrator-trusted canonical absolute
`sandboxPolicyContainerdSocket` path. The socket and its parent must be
protected from workload substitution. The host root/proc mount must be a trusted
host mount, not a workload-supplied path. Unsupported kernels, runtimes and
images refuse admission rather than falling back to another engine.

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
module defaults below (`/sys/module/overlay/parameters`: `index`,
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
- Restart survival: get its own pod, and get/list/watch DaemonSets (`apps`) in
  the agent namespace, to tell an uninstall from a restart at shutdown.
  Without them the pinned sets stay after an uninstall until the node reboots
  (fail closed).

This change does not grant chart RBAC, change a chart version or store policy in
SQLite/files. Kubernetes owns the CRD objects. Per-policy/node status resources
are output; the agent does not write parent aggregate status.

Each report carries `appliedGeneration`, the oldest policy generation still
installed on the node, counting container bindings and privilege pod cgroup
bindings. It stays on the last-good generation while a newer revision is
rejected, and is absent when no binding enforces the policy. `stale` is set only
when an installed binding lags the desired generation or its protection cannot be
confirmed: a failure that leaves the current generation enforced is `Ready=False`
with `stale: false`, and its message says "applied on N binding(s), failed on M":
N bindings enforce the desired generation and M bindings that select the policy
failed to apply it in the last reconcile. When no binding failed to apply it (a
withdrawal or the snapshot failed), the message says "applied on N binding(s);
another step failed". At
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
moves to its new slot, unconfirmed; it keeps its last-good binding until that
slot is ready, and a pod whose cgroup changes keeps its old binding until the
new cgroup's slot is ready. A pod plan keeps last-good per policy, as a container
binding does: a policy that is invalid, has a class error or does not compile
keeps its version from the pod's last plan (or is left out), and the other
policies still apply. Too many policies keep the pod binding as it is. While
the instance is not ready, every pod binding is unconfirmed.
A pod binding whose slot has a fault makes the policy report
`ProtectionUnconfirmed`. For a Strict slot a node tracking fault (a lost child
mark of a `CLONE_INTO_CGROUP` fork anywhere on the node) is a fault too. A heal
arms the bound tasks again in the running instance (no reload) and restarts the
count; node faults alone heal at most every 10 minutes, because their cause may
persist. A heal cannot confirm a slot that a pod binding covers (a pod binding
never arms), so such a fault stays reported. When a fault counter or the node
witness cannot be read, and nothing else is wrong, the policy reports
`Ready=Unknown` with reason `WitnessUnknown`: the protection is unknown, not
lost. A real fault next to it keeps `ProtectionUnconfirmed`. A pod binding
reports only that it is faulted, so a policy with a faulted pod binding
reports `ProtectionUnconfirmed`, also when the cause is an unreadable counter.
The privilege instance is not ready while its credential record (the
overridden credentials it judges, see the gadget README) is at least 90%
full: a Strict binding would soon be refused new credentials.
A new Strict binding (privilege or file section) whose container holds io_uring
rings opened before it is refused: the policy reports `NotReady` with reason
`IoUringHeld`, and the refresh binds it once the rings are closed (an io_uring
worker thread that stays after that does not count). A workload that opens its
rings at start opens them again after a restart, so it stays refused until it
closes them. Upgrade note: Strict bindings written by an agent from before the
io_uring check flag (`BINDING_RING_CHECKED`) carry no flag, so the first agent
that takes them over checks them again: a container that opened its rings after
its bind is then refused (`IoUringHeld`) and its old binding stays enforced but
`ProtectionUnconfirmed`, until it closes those rings (for a workload that keeps
its rings open, until it restarts without them). An Audit binding with rings binds; the policy reports
`Degraded=True` with reason `IoUringHeld`, and the agent logs a warning.

The slot sections (privilege, network, file) load on every kernel IG admits,
the same way as the shared exec engine and with no kernel list. The root
barrier loads with the file section, so the file section's check gates it
too. At start each section runs IG's kernel admission
(`fullruntime.AdmitKernel`, the same checks as the shared exec engine's gate;
see [Shared engine: supported kernels](#shared-engine-supported-kernels)):
x86_64, `bpf` in the active LSM list, `ftrace_enabled=1`, no livepatch and a
readable identity (BTF sha256, release, GNU build-id). The section's own load
then checks its types and attach targets (CO-RE and the verifier).
Configuration never changes the check. When it fails, the section's gadget is not loaded, nothing
falls back, and every policy with that section reports `tier: none` and
`Ready=False` with a reason from the failed check: `<Section>KernelUnqualified`
(another architecture, or an unreadable identity; for example
`NetworkKernelUnqualified`), `BPFLSMInactive`, `FtraceDisabled` or
`KernelLivepatched`. On a kernel the suites did not run on, hook ordering and
verdict semantics are not proved by a suite (see
[What is and is not proved](#what-is-and-is-not-proved)). The check runs once
at start: a section refused at start stays unloaded until node-agent
restarts, even after the node is fixed.

Ftrace and livepatch are re-read at every status write. Ftrace is detected,
not guarded: with `ftrace_enabled=0` the BPF LSM trampolines do not run, so a
deny becomes an allow. While the check fails, every policy with a loaded slot
section reports `tier: none`, `Ready=False` (`FtraceDisabled` or
`KernelLivepatched`), `stale: true` and no applied generation: its bindings are
unprotected until the check passes again. The root barrier's attestation also
reads `/proc/sys/kernel/ftrace_enabled` (from procfs only) at each check and
fails unless it is 1, so a Strict file slot is refused while ftrace is off. A
kernel without `CONFIG_FUNCTION_TRACER` has no such file, so the attestation
fails there (closed).

Hook canary. An attached link is not a hook that runs (bpf missing from the
boot `lsm=` list, ftrace off, a hook call the kernel never switches on). Right
after each start of a privilege, network or file instance (in the background:
the start does not wait), and then every 5 minutes while it runs, node-agent
proves that the section's BPF LSM programs run: it uses the exec engine's
attach canary (IG `fullruntime.RunAttachCanary`), which turns on BPF run
statistics, runs a child, and requires the run count of each program to rise.
The child is node-agent itself
(`/proc/self/exe __sandbox-section-canary <hooks> <dir>`), which exits in
`init` after one harmless call per hook (`igbackend/canary_child_linux.go`):
AF_UNIX `connect` and `sendmsg`; file calls in a temporary directory that
node-agent makes and removes; the root barrier's no-op mount probes; its own
keyring, IDs and capabilities; an exec of a missing path. Only the run counts
decide. One exception: a hook that did not run, and whose every call was
refused with EPERM, EACCES or ENOSYS, or whose call could not get the file or
io_uring ring it needs, may have been stopped before the hook by another layer
in node-agent's container (seccomp, a missing capability, another LSM). It is
reported as not proven, not as silent. ENOSPC counts only for `userns_create`
(the user namespace quota comes first), and a fork's EAGAIN only for
`task_alloc` and `ptrace_traceme`. `cred_alloc_blank`'s call gets EPERM after the
hook on a working node, and seccomp or an LSM at the keyring lookup can return
it before: its EPERM counts too, and a rising run count still proves it. For
`uring_override_creds` the call's result is the no-op request's completion.

Hooks not proven to run are in the status of the section's policies; Ready
stays True, because the section enforces. Three privilege hooks have no
harmless trigger on any node (`kernel_read_file`, `kernel_load_data`,
`kernel_module_request`): the Ready message names them. A hook not proven on
this node (a refused call, or `uring_override_creds` and `userns_create` on a
node where io_uring or user namespaces are off) makes the policy `Degraded`,
reason `<Section>HooksUnproven` (for example `PrivilegeHooksUnproven`), with
each hook and why. node-agent logs them at every canary run. From the start of a
section instance until its first canary result, its policies are not Ready
(`<Section>CanaryUnavailable`, "has not run yet"). The result is read at every
status write, after the ftrace and livepatch check:

- a hook that did not run: `<Section>HooksSilent` (for example
  `PrivilegeHooksSilent`), latched until node-agent restarts;
- a canary that could not run (run statistics, the child, its temporary
  directory, a missing link): `<Section>CanaryUnavailable`, retried after 30
  seconds, then 60, and latched after 3 failures in a row.

Both report like `FtraceDisabled`: `tier: none`, `Ready=False`, `stale: true`
and no applied generation. Like ftrace, it is detected, not guarded: the
instance stays loaded. Cost: one child process per section every 5 minutes;
while the canary runs (under a second), every BPF program on the node also
counts its run time. Each instance start waits for its first canary: under a
second on the AL2023 kernels, at most 5 seconds (the budget) when a hook is
silent or its call is refused.

Runtime reporting rule. The slot sections count, per slot, the judged checks
and forks (attempts), the fail-closed refusals and faults of Strict bindings,
and the judgements Audit bindings lost; arming sections add node faults (a
lost child mark of a `CLONE_INTO_CGROUP` fork, whose target cgroup is not
known) and, with the operator's consent, exempted execs. A node fault counts
as a failure of every Strict slot and as a notice of every Audit slot: it makes
an Audit policy `Degraded` for 60 s, never `NotReady`. The counters are pinned, and the
owner samples them at every service refresh (about every 5 s) into a window
that survives heals, reloads and new instances. A policy that is otherwise
Ready reports `Ready=False` with reason `FailClosedRate` when more than 0.1 % of
the attempts failed over 5 minutes, `Ready=Unknown` with reason
`WitnessUnknown` when a counter cannot be read or moved backwards (never a zero
rate). Its own `Degraded` condition is `True` (`FailClosedRecent`) after any
failure in the last 60 s, `Unknown` (`WitnessUnknown`) when a counter cannot be
read, else `False`. It is also `True` (`VerdictsSuppressed`) when a section of
the policy counted denies with no verdict event in the last 60 s (the kernel's
per-CPU report limit, 100 reports per CPU per second, or a full ring buffer). That loses
evidence for every consumer (log and export), not enforcement: `Ready` keeps its
state. The count is per section for the whole node, so every policy of that
section on the node shows it. With a stronger reason the note is added to its
message. When a verdict counter cannot be read (or the counters were created
again), the loss cannot be counted: `Degraded` is `Unknown`
(`VerdictLossUnknown`) until a full 60 s of readable samples follows, never a
zero loss. On a node with the shared exec engine, its status writer keeps an
`Unknown` `Degraded` condition of the sections; a degraded shared node makes it
`True` and the `Unknown` reason moves to the message. The `node_agent.sandbox_policy.section_kernel.events.total` metric (`rate_limited`,
`dropped`) has the same counts. A Strict slot fault also keeps the binding
`ProtectionUnconfirmed` until a heal arms its tasks again; a reload alone does
not clear it. A policy edit (a new policy combination) starts a new window, so
the policy reads `Ready=Unknown` (`WitnessUnknown`, "less than 1m0s of counter
samples") for about 60 s after each edit, until the window holds a full minute
of samples.

Lost verdicts leave summary records. Each section gadget counts a rule decision
it could not report (rate limited, or a full ring buffer) in a hash map
(`verdict_summaries`, 4096 keys) under its generation, slot, rule, hook, detail
(the privilege capability and syscall, the file access kind), mode and cgroup,
with the count, the first and last time, and the first and last task (pid and
name). Nothing is evicted: once a hidden attempt has its key, a flood cannot
remove it. When the map is full, a new key is not added; that deny is counted in
the `summary_overflow` result of the section kernel metric (an insert that
fails for lack of memory counts there too), and the `VerdictsSuppressed`
message says how many lost denies have no summary record.
The task name is in the value, not the key, so renaming tasks makes no keys. A
hidden attempt that shares the flood's key (same rule, hook and detail; under a
default deny, the default rule) is counted in the flood's summary. The service
drains the map at each refresh (about every 5 s), and drains an instance before
and after it stops it. It logs one `sandbox <section> verdict summary` line per
key (rule, mode, hook, detail, tasks, cgroup, container, count, reason, first,
last), and gives the record to the section receivers that implement
`sandboxpolicy.VerdictSummaryReceiver` (none yet: the export schema for
summaries is a follow-up). A summary has no path or destination. Counts are
approximate: an element the drain deletes can be reused at once, so a deny
counted just then can land on the next key that uses it (rarely another
cgroup's); the `rate_limited` and `dropped` counters stay exact. Root barrier denials and operational faults that
hit the limit are not summarized (only the counters). After a restart, a
previous run's kept links count their lost denies in their own summary map,
which no process drains: those have the counters only.

The `ActiveRevision` condition lists each installed generation with its
binding scope: `scope=exact` for a container cgroup binding, `scope=subtree`
for a pod cgroup binding (it covers the cgroups of that pod's containers, and
nothing outside the pod).

Pod cgroup bindings do not exempt OCI runtime helpers by default: a
createContainer or startContainer hook that runs inside the pod cgroup is
judged like the workload, so a Strict policy that denies what the hook does
fails the container start. The host operator can consent to the exemption with
`sandboxPolicyRuntimeHelperExemption: true`. Pod bindings then carry the
`RuntimeHelpers` flag, and each policy with such bindings reports the
`RuntimeHelperExemption` condition with the number of flagged pod bindings and
the execs the exemption left unjudged on the node (`ExemptExecs`; `Unknown`
when the counter cannot be read).

Each section (privilege, network) runs one long-lived node-wide gadget instance.
A new or changed policy combination is compiled alone and published into a
free slot of that instance: the policy is written into the slot's inactive
buffer, then one map write flips the slot (no BPF reload, no second instance).
A failed publish keeps the last-good policy. A slot no binding uses is freed
and reused only after a quarantine (2 s). Prepare keeps 4 slots free for the
combinations of starting containers; a container that finds no free slot drops
the slots only Prepare wanted, and binds at the next try. The instance is
replaced only when it is not ready.

A privilege change commits in two phases: the privilege slot is prepared first
(a publication into the running instance; it binds nothing), then exec
commits, then the privilege bind is a live map write. A failed prepare leaves both sections on
their last-good plan. Removing the privilege section withdraws it first: a
withdraw on an instance that is not ready stays pending and is retried, and exec
does not change meanwhile.

## Shared engine: supported kernels

The G020 shared node engine runs one node-wide IG collection for every
binding; it is the only exec engine. The agent selects the engine itself, at
start, from the running kernel; configuration never selects it. The IG
contract is in the IG `gadgets/enforce_exec/fullruntime/README.md`, section
"Shared engine: supported kernels", which this section follows.

### Engine selection

Every kernel is admitted the same way, by IG's probes; there is no kernel
list. At start the agent
(`pkg/sandboxpolicy/integration/engine_kernels.go`, `selectKernelEngine`)
runs IG's product kernel gate (`fullruntime.SharedProductKernel`): x86_64, a readable vmlinux BTF sha256,
release and GNU build-id, `bpf` in the active LSM list, `ftrace_enabled=1`
and no livepatch. It logs the admitted kernel's release at start.

| Running kernel | Engine | Policy node status |
|---|---|---|
| Any kernel IG's gate admits | shared engine on the compiled-in image | as below (`SharedNodeNotReady`, ...) |
| A kernel failing bpf LSM, ftrace or livepatch | none | Ready False, `SharedEngineUnavailable` (the check) |
| A kernel of another architecture, or with an unreadable BTF digest, release or build-id | none | Ready False, `KernelNotQualified` (the failed check) |

Nothing falls back to another engine or image. The shared engine runs IG's
gate again when it is built (at agent start) and right before the node
starts, and IG runs it a third time in `StartNode`. A failed or malformed gate
result never starts the node.

The product object also carries IG's root barrier: seven `rb_*` LSM programs
(`path_chroot`, `sb_pivotroot`, `userns_create`, `capable`, `sb_mount`,
`move_mount` and `sb_umount`). At start, after the attach checks and before the
canary, IG attests the barrier's links and runs its self-test
(`rootbarrier.Verify`). A failure leaves the node NotReady
(`SharedNodeNotReady`). The barrier has three preconditions that the gate
above does not probe, so a kernel can pass the gate and still fail here:

- the `userns_create` LSM hook (Linux 6.1+). Without it `rb_userns` cannot
  attach, and the start fails with a start error, not `SharedEngineUnavailable`;
- user namespaces enabled (`user.max_user_namespaces` > 0), or the self-test fails;
- the agent's `CAP_SYS_ADMIN` and `CAP_SYS_CHROOT`, and no AppArmor profile
  that denies `mount` (the chart runs the agent AppArmor unconfined). The
  container runtime's default set gives `CAP_SYS_CHROOT` on containerd, not
  on CRI-O, so on CRI-O the agent needs it added explicitly.

The barrier's faults are a fail-closed class of their own in IG's health; they
reach the policy status through the shared node's Degraded and NotReady states.

### What is and is not proved

On every admitted kernel, at start and while it runs:

- the product object's own load checks every type, field, kfunc and attach
  target it uses (CO-RE relocation and the verifier);
- IG probes `FMODE_BACKING` and the overlay `private_data` layout live. A
  failed `FMODE_BACKING` probe does not refuse the engine: image-origin facts
  are then unavailable, the node reports them Degraded and `fromImage`
  policies are refused, while path rules keep enforcing. A failure is never
  cached, and no kernel has a pinned fallback;
- the exec engine's startup canary proves every attached program of the
  product object runs (the privilege, network and file sections have their own
  canary, with the hooks it does not prove: see "Hook canary");
- the live witness latches NotReady when an exec or fork reaches its
  tracepoint without its LSM hook's mark, or when ftrace goes off.

Not proved on a kernel the kernel suites did not run on: hook ordering and
verdict semantics across the exec paths. CO-RE relocates field offsets but
cannot prove those, nor exec-path behaviour changed by vendor backports under
the same version string. There is no startup deny self-test: a test binding
would hold one of the shared engine's route slots until the node stops.

The node's identity (BTF sha256, GNU build-id from `/sys/kernel/notes`,
release from `uname -r`) must be readable, and is reported, not matched
against a list. Ftrace and livepatch are re-read at every node Ready. Ftrace
is detected, not guarded: root can set `kernel.ftrace_enabled=0` on a running
node (the kernel accepts it), the BPF LSM programs then stop running (a
denied exec is allowed), and the shared node's Ready reports NotReady.
Treat a node whose shared Ready fails as unprotected; this is an accepted,
detected limitation. IG also checks the loaded eBPF object: its sha256 must
be one of IG's product objects, on every kernel alike.

### Compiled-in image

The agent compiles in one product image and ships it inside the agent image's
`tracers.tar`. A product image is kernel-neutral (one CO-RE object per
profile), so the same image runs on every admitted kernel:

| Image (in `tracers.tar`) | Profile | amd64 manifest digest |
|---|---|---|
| `enforce-exec-shared:g19pkg128` | `g19pkg128` | `sha256:48b5584528ce98f2b05463470a64ae994a73134f7d1ccf9434c2110e3bf5a182` |

- The name, the manifest digest and the profile (`SharedProfile`) are IG's
  `fullruntime.SharedProductImagePins()` entry for `g19pkg128`
  (`compiledProductImage`); `TestCompiledInImageMatchesIGPin` fails when an
  IG bump rotates the pin until the agent is updated.
- The image is never pulled from a registry. `make gadgets` (target
  `product-images`) checks out the IG commit that `go.mod` pins, runs its
  `make enforce-exec-product-images` there (the pinned clang container, then
  `cmd/productimages`, which builds IG's 4 pinned images, one per profile,
  and fails unless every manifest and index digest equals IG's pins; it runs
  in the IG checkout because the digests depend on IG's own module
  versions), imports the layout into ig's local store and exports
  `enforce-exec-shared:g19pkg128` into `tracers.tar` next to the other
  gadgets. It needs git, docker, go and `sudo ig`.
- `make check-product-images` opens the built `tracers.tar` and runs the
  agent's manifest selection on the compiled-in image for amd64 (not the
  builder's architecture), then fetches every blob the selected manifest
  references, digest-verified (`igbackend.VerifySharedImage`).
  `make docker-build` and the release workflow run it before building the
  agent image, so an agent image cannot ship with a missing or different
  product image.
- At start, and again before the node starts, the agent resolves the image
  in `tracers.tar` the way IG does and refuses an image whose `amd64`
  manifest digest differs, or an index with more than one `amd64` manifest or
  a manifest without a platform. The manifest content-addresses the config
  and the eBPF layer.
- `sandboxPolicySharedImageProcRoot` and `sandboxPolicySharedImageHostRoot`
  (default `/host/proc` and `/host`) locate the host procfs and root; the
  chart takes them as `sandboxPolicy.imageProcRoot` and `imageHostRoot`.
- `sandboxPolicyImage` is a legacy key: not required and ignored; a
  non-empty value is reported once at start.

**Release note.** Upgrading to this version turns enforcement on for every
node that IG's gate admits and that has `sandboxPolicyEnabled: true`: the
shared engine starts on the compiled-in image, with no chart change.

**Older configuration (deploy skew).** `sandboxPolicyEngine` and
`sandboxPolicySharedImages` are deprecated and ignored by the default build.
`sandboxPolicyEngine` `""`, `"full"` and `"shared"` all load (any other value
is still a configuration error). `sandboxPolicySharedImages` is still
decoded, but it can no longer supply an image: it is not validated and never
used. A non-empty value of either key is reported once at start at Warning
level ("sandbox policy configuration"), not as an error. So a chart that
renders `sandboxPolicyEngine: "shared"` and the image map keeps working
unchanged.

**Rollout order.** Three agent version floors govern the chart keys:

- **Engine floor:** the first release with commit `bec29be9` (the engine is
  selected from the running kernel). Agents older than it refuse
  `sandboxPolicySharedImages` without `sandboxPolicyEngine: "shared"`, and
  `cmd/main.go` makes that refusal Fatal: the whole node-agent crash-loops,
  not just sandbox enforcement. While any such agent may run, the chart must
  keep rendering `sandboxPolicyEngine: "shared"` whenever `sharedImages` is
  non-empty. Drop `sandboxPolicyEngine` only once every agent is at or above
  this floor.
- **Image floor:** the first release with compiled-in product images. Agents
  below it have no compiled-in image: they enforce only through a
  `sandboxPolicySharedImages` entry, and only with a custom-built
  `tracers.tar` that holds that image (no released agent image below this
  floor ships one). Drop `sharedImages`, the profiles ConfigMap and its mount
  only once every agent is at or above this floor.
- **Legacy-key floor:** the first release without the per-binding engine.
  Agents below it refuse to load a sandbox configuration without
  `sandboxPolicyImage` and a canonical, non-root `sandboxPolicyControlRoot`,
  and `cmd/main.go` makes that refusal Fatal. While any such agent may run,
  the chart must keep rendering both keys with valid values; this agent
  ignores them (one warning at start). Drop them only once every agent is at
  or above this floor.

In the chart, `nodeAgent.config.sandboxPolicy.sharedImages` (default empty)
is only for agents below the image floor; this agent ignores it. The chart
refuses `sharedImages` together with `sharedQualification`. A qualification
build (tags `sandbox_shared_qualification,enforce_exec_shared_qualification`,
deployed with `values-shared-qualification.yaml`; never Ready, and the only
build with the verdict-log receiver) refuses the map, and the default build
refuses `sandboxPolicySharedProfileFile` whatever the engine. A refused
kernel, a missing image, a manifest mismatch or a bad profile does not stop
the agent: it is reported as above, with the reason (it wraps
`ErrSharedNativeUnavailable`).

Qualification builds (`sandbox_shared_qualification`) keep the explicit
`sandboxPolicyEngine` key but require `"shared"`: `""` and `"full"` are
refused at service start. They run the shared candidate image `sandboxPolicyImage` names.

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
  (`SharedNodeNotStarted`). While a node start is still retrying a native
  attach capacity refusal (IG's bounded attach retry), Ready is False
  (`SharedNodeAttachCapacity`, with the refusal); each refusal is also logged,
  at most once per 10 s with the count suppressed since. It returns to the
  reasons above when IG reports the refusal cleared or the start ends. This
  is status only: enforcement is unchanged. A failed node start is Ready False
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
  `AgentStopping` (`SharedNodeNotReady`, `KernelNotQualified`,
  `SharedEngineUnavailable`, `SharedNodeNotStarted`, `SharedNodeAttachCapacity`,
  `SharedNodeStartFailed` or `QualificationOnly`);
  Ready is False either way. Active policies without exec rules keep their
  last report: they never enforced anything.
- `appliedGeneration`: the policy generation the node enforces now, the
  oldest one among its confirmed bindings for that policy. It lags
  `observedGeneration` while a rejected revision leaves the last-good
  bindings in place. It is absent when no binding is confirmed (none
  committed, or protection unconfirmed), in the `AgentStopping` report, when
  the shared engine is unavailable, not started or NotReady, and when an
  installed generation is newer than the observed one (admission rejects
  `appliedGeneration` above `observedGeneration`). A qualification build never
  reports it: its bindings are never confirmed. Policies the stop report skips
  (no exec rules, or Off with a withdrawal that did not commit) keep their last
  report, `appliedGeneration` included, after a graceful stop.

### Operational facts and what is unproven

- An agent crash or restart leaves enforcement **off until the agent is
  restarted**: the in-kernel state dies with the agent's BPF objects. A
  graceful stop writes Ready False (`AgentStopping`) before enforcement is
  withdrawn. Enforcement is off between agent processes during a restart, for
  already-running pods too. The agent starts the service as soon as the
  container collection is initialized, before the `procfsScanInterval` wait
  (default 30 s) and the observability tracers' 2 s staggered start. The collection then holds the containers
  the runtime listed as running, enriched; if that listing fails, IG only
  warns and the collection starts without those containers. The procfs scan runs during the service's start;
  the eBPF tracers start only after it has returned, so a BPF load during that
  start does not overlap theirs (a later load, for example a node start on a
  policy created then, can). The trade-off: when the service's start takes
  longer than `procfsScanInterval`, the eBPF tracers (observability) start
  later, by at most `FullStartupTimeout` plus 30 s from the service's launch.
  Past that bound the agent logs an error, starts the eBPF tracers and
  finishes the container watcher's start, so `/readyz` answers and the pod
  can turn Ready before enforcement has started (as it always did before this
  order). The agent still waits for the service's start, logging an error,
  before it starts the generic watchers: a start that never returns leaves
  the agent Ready with enforcement not started. The agent catches SIGTERM and
  SIGINT from before the container watcher's start: a signal received during
  the start (that wait included) is held and handled once the agent's
  startup completes, through the normal shutdown (`AgentStopping`, then
  withdrawal). If startup does not complete within the pod's termination
  grace period,
  the kubelet kills the agent and no `AgentStopping` is written. A start that
  fails is
  still fatal. If the container watcher fails after the service started, the
  service is closed before the agent exits; with FIM enabled the agent instead
  continues in FIM-only mode with the service running. If the container
  collection itself fails while sandbox policy is enabled, the agent exits
  even with FIM enabled: it does not continue in FIM-only mode without
  enforcement while the previous agent's last report stands. The restart gap
  has not been measured. A graceful stop is reported by `AgentStopping`; a crash restart was not exercised. A crash or SIGKILL cannot write anything, so the last report
  (possibly Ready True) stays. The agent writes a report when its content
  changes (within one refresh, about 5 s; within one minute when only the
  counts in a condition message change) and otherwise refreshes
  `lastReported` as a heartbeat every 5 minutes (`StatusHeartbeat`):
  consumers should treat a report whose `lastReported` is older than three
  heartbeats (15 min) as NotReady. So after a crash a report can show the last
  Ready True for up to 15 min; a graceful stop is reported at once
  (`AgentStopping`). A pass that starts the node (up to `FullStartupTimeout`,
  2 min) delays the first report. Until the restarted agent writes its first
  report, the previous report stays visible: Ready True while its
  `lastReported` is at most 15 min old, and NotReady after that. The restarted agent
  reports Ready True only after its bindings are protected again (node Ready
  and each binding confirmed).
- **Unproven:** SELinux enforcing; lockdown modes other than none; other BPF
  users beyond the synthetic coexistence tests; arm64; hook ordering and
  verdict semantics on any kernel no kernel suite ran on (admitted, but not
  proved). Taints other than livepatch (out-of-tree or unsigned modules) are
  allowed. The default build has no fact counters.
- Argv predicates are refused (D1). The AT_EXECVE_CHECK and RETIRING residuals
  (D3/D4) and the migration-out residual apply (see the IG README). One policy
  per binding: multi-policy plans are refused (D3).
- IG re-resolves the image name in the same read-only `tracers.tar`; the agent
  binds the manifest digest and IG binds the loaded object's sha256 to the
  pinned objects.

### Future work (not implemented)

1. **Startup deny self-test:** load, probe execs, check hook firing and
   ordering, then enable.
   - Pro: broad coverage.
   - Cons: proves only the exercised paths (races, binfmt_misc, ptrace and rare
     paths stay unproven); needs a test cgroup on production nodes; adds
     startup latency; a false pass is a silent bypass.
2. **Audit-first, promoted to Strict after a clean period.**
   - Pro: no outage risk; reuses the fail-closed witness thresholds.
   - Cons: missed hooks look clean; the clean period is arbitrary; no
     protection meanwhile; promotion needs an operator.
3. **Targeted BTF matching** of the functions and types the object depends on,
   beyond what CO-RE relocation checks.
   - Pro: survives unrelated backports.
   - Cons: types do not prove semantics or call order; the dependency set must
     be complete and maintained; a gap is a silent bypass.
4. **Bulk kernel-family qualification** (stock-kernel matrix,
   kubescape/inspektor-gadget#27).
   - Pro: today's proof strength.
   - Cons: about an hour of EC2 per kernel; needs a pipeline that tracks
     vendor updates; the evidence lags new AMIs.

The likely combination is (4) for evidence claims, with (3) and (1) only as a
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
retries cleanup and rebuilds every status report.

**Status writes.** A rebuilt report is written only when it differs from the
stored one, ignoring `lastReported`; an unchanged report is written again only
when its stored `lastReported` is 5 minutes old (the heartbeat). A change of a
condition's status or reason, a generation, `stale`, `tier`, `error` or any
other field is written in the same refresh. A change of only the numbers in a
condition message (counts that move with traffic, such as denies without a
verdict in the last minute) is written at most once a minute; the
`ActiveRevision` and `AdoptedLastGood` messages name generations, so any change
in them is written at once. The causes in
`error` are sorted, so a lasting failure of several bindings reads the same on
every refresh. So an idle node
changes a report's `resourceVersion` at most once per 5 minutes, which keeps
the load low for etcd and for a synchronizer that copies the reports.

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
the shared engine's route slots. Per binding the compiler bounds eight policies,
256 rules, 1,024 patterns, 256 predicate values and 16,384 IR entries. Paths may
contain at most 255 encoded bytes; argv capture is bounded to 64 arguments and
4,096 bytes. Oversized or unrepresentable candidates are rejected as a whole.
Kernel admission is described in
[Shared engine: supported kernels](#shared-engine-supported-kernels).

ContainerProfile import currently requires a completed profile with full
coverage, an unambiguous selected container and literal paths. Exact argv-length,
argument-wildcard and environment constraints cannot be represented faithfully by
the CRD exec vocabulary and are refused rather than broadened.

When an exec section denies by path (a deny rule with paths, or `default: deny`),
the compiler adds the deny rule `node-agent-loader-deny` (origin `node-agent/loader`,
the strongest mode of those denies) on `/**/ld-*.so*`, the glibc and musl dynamic
loaders; otherwise `ld.so <program>` runs a denied program through an image-allowed
loader. It applies to every actor, also when the denies it protects are scoped by actor
or argv. So `ldd` stops working, and so do launchers that exec the loader explicitly:
AppImage, some Nix and Bazel wrappers, and scripts that run `ld.so --library-path`.

An allow rule whose path names a loader file keeps loaders runnable for the whole policy,
for every actor, even when the allow is scoped to one actor: then no rule is added. A
path names a loader when its file name starts with a literal `ld-` and matches a known
amd64 or arm64 loader name (`ld-linux-*`, `ld-musl-*`, `ld-2.31.so`). A library glob such
as `/usr/lib/**/*.so*` does not name a loader, and neither does another name such as
`ld-2.28.so` or `ld-linux.so.2`: the loader deny stays. The directory is ignored, so an app
that ships its own loader (`/opt/app/ld-linux-x86-64.so.2`) also keeps the image's loaders
runnable. This also applies to allow rules from a path class or a ContainerProfile source:
a profile that recorded an `ldd` run turns the loader deny off. The status reports this in
the `ExecLoaderAllowed` condition (reason `LoaderAllowRule`), with the rule, its origin and
the path that caused it.

**Upgrade note for existing exec policies.** Before upgrading from a version
without the generated loader deny, review both namespaced and cluster policies:

```sh
kubectl get sandboxpolicies -A -o yaml
kubectl get clustersandboxpolicies -o yaml
```

For each section that will gain the rule, leave room for one more rule
(at most 255 resolved rules before insertion) and about 20 more encoded
cells in the product image's 256-cell policy object. Count imported
ContainerProfile rules and expand path classes for each selected container.
A short rule list can still fill the object through paths or other predicates.

For policies near either limit, test the new agent on a staging node with
matching workloads, classes and profiles before rolling it out. Inspect
`kubectl get sandboxpolicynodestatuses -A -o yaml` for the desired generation
and its Ready condition. If the compiled object is too large, the exec policy is
not installed and the error gives the required and available cells. A previous
exec revision of the container, if any, stays enforced. The refresh retries the
policy, but it cannot bind until the policy is reduced. A policy
with only exec rules reports Ready=False with reason `ExecPolicyTooLarge`; a
policy whose other sections still install reports `ProtectionUnconfirmed`. Reduce redundant rules or predicates
and verify the revised policy in staging. An existing API object can survive
the upgrade even when a new binding cannot install its exec policy.

The loader rule closes the bypass only where a copied program cannot run. Under
`default: allow`, a path deny is not a hard boundary: `cp /usr/bin/id /tmp/x && /tmp/x`,
or a copy of the loader, still runs from any writable directory where exec is allowed.
Use `default: deny` with `allow fromImage`, or a read-only root filesystem with `noexec`
volumes, when the deny must hold.

## Node-agent restart (privilege, network and file sections)

The node gadgets of the privilege, network and file sections keep enforcing when
node-agent exits (clean shutdown, SIGKILL or OOM). Each section runs one
long-lived instance per node on one shared state: its maps are pinned by name
with a versioned prefix (`sbx1_priv_`, `sbx1_net_`, `sbx1_file_`). node-agent's
`/sys/fs/bpf` is private to its container, so each node owner also pins the
state maps and the program links of its run under the host bpffs
(`/sys/fs/bpf/kubescape-sandbox/<section>/<run>/`, reached through the host root
mount), with a manifest of the published slots (policies, revision digest,
generation). Without a host bpffs, restart survival is off and a warning is
logged.

- **Restore.** At start each owner validates the pinned sets (manifest, section,
  boot, links and maps of the set) and restores the state maps of a valid set
  before its first instance starts. A set is removed at start only for a proven
  cause: another boot, an unfinished set (`_tmp`), a missing manifest, a pin the
  manifest does not list, or an ID, tag or layout mismatch. A set that cannot be
  read (an I/O error) is kept as an old set, not restored, until the section
  settles; so is an old set whose bindings map cannot be read. Their policies
  are not known, so every policy of the section reports them
  (`AdoptedLastGood` `Unknown`, `AdoptedLinkMissing`). A failed boot ID read turns restart survival
  off for this run and keeps every pin: the next run with a good boot ID
  decides.
- **Adopt.** The new instance re-opens the state and adopts what it finds: the
  published slots, their class (Strict or Audit) and the kernel bindings that no
  container of this run has taken over yet. Those keep enforcing what the
  previous run enforced; a container that binds takes its binding over. The run
  pins its own set; the old links go once the new instance is ready.
- **Settle.** Each section settles on its own, after a refresh with a complete
  binding snapshot where the controller built every binding's full plan (no
  policy error, no retiring binding, every pod cgroup found) and the section's
  own bindings and pod bindings all committed: a failing binding of another
  section or a failed status write does not hold it back. It drops the adopted bindings no container took over, frees the adopted
  slots this run does not use, and removes the old sets. If a section does not
  settle within two minutes, each adopted binding is decided from the current
  plan of its cgroup: it is dropped when that plan is now Audit (Audit never
  blocks), and kept when it is Strict or not known yet, for example while the
  binding snapshot keeps failing (fail closed). A binding whose cgroup has no
  plan of the section is dropped once a complete binding snapshot was seen (its
  policy was removed, or its container is gone); before that it is kept. While
  any stays, the section is degraded. A reload of a gadget before settle keeps
  the adopted state.
- **A failed restore.** When the state is not restored (another image, an
  unreadable set), the new instance starts fresh and the old sets keep
  enforcing until the section settles. Before that, each cgroup leaves an old
  set on its own (node-agent deletes its entry from the set's pinned bindings
  map): at once when it has a committed binding of this run or an Audit plan,
  and, past the deadline, when it has no plan and either a complete snapshot
  was seen or its policies are all gone from a complete policy listing. A set
  with no entry left is removed. So a Strict container whose new bind keeps
  failing stays enforced by the old links, and the other cgroups of the same
  set are not held by it (Audit never blocks). A set whose bindings cannot be
  read stays whole. On the restored path, the sets of an older run (another
  state) follow the same rule, also before the deadline and while the
  instance is not ready. A cgroup that leaves an old set is still judged by
  that set's entry of a bound parent (its pod cgroup, a subtree binding)
  until that entry is covered too: at once with an Audit pod plan; when the
  pod has no pod plan, past the deadline once a complete snapshot was seen or
  its policies are gone from the listing (fail closed until then). A pod
  entry whose Strict bind stays pending keeps judging its containers until
  the section settles. When the
  cgroup's wanted plan is Strict, only a committed Strict binding covers it.
  Status reports the old sets as adopted, from their pinned bindings and
  manifests. A gadget that fails 3 first starts on a restored state (not for
  attach capacity) gives that state up the same way: the next start is fresh,
  and the old sets follow this rule. The deadline keeps an adopted binding by
  the last plan the controller asked for, bound or not; a section that the
  plan stops using is withdrawn, also when its last bind failed, so it forgets
  that plan.
- **Removed policies.** Adopted bindings whose policies are all gone have no
  policy status to report them. The node reports them: the gauge
  `node_agent.sandbox_policy.adopted_without_policy` (attribute `section`)
  counts them, and a warning is logged when the count changes. Past the
  deadline they go once a complete policy listing no longer names any of their
  policies (by UID, or by namespace and name: a policy created again under
  the same name keeps them), without waiting for the whole node to converge (a broken policy
  elsewhere does not hold them); a failed listing removes nothing. A section
  left with no plan and no instance settles the same way. A policy that is
  still listed but no longer uses the section, or is off, still waits for a
  converged refresh or a complete snapshot.
- **Status.** While adopted bindings still enforce a policy, its node status has
  an `AdoptedLastGood` condition with the section, slot, revision, generation,
  digest and number of adopted bindings: the revision that actually runs. Past
  the deadline its reason is `SettleDeadlinePassed`, and so is the reason of the
  policy's `Degraded` condition (`True`), except after fail-closed checks (`FailClosedRecent` stays the reason and the deadline is added to its message); a `VerdictsSuppressed` or `WitnessUnknown` message is kept in the deadline message. Each status read checks the links of the previous run's pinned
  sets again (by link and program ID, at most every 5 s); a link that no
  longer runs its program makes the condition and Ready `Unknown`
  (`AdoptedLinkMissing`). In the restored path the old sets that ran on the
  restored maps are removed as soon as the new instance is pinned; from then
  on `AdoptedLinkMissing` covers nothing, and the running instance's own link
  check (`Attached`) protects the adopted bindings. The `RestartSurvival`
  condition is `True` (`Pinned`) only when every section the policy uses
  survives a restart; `Unknown` (`PinPending`) while a section is not pinned
  yet; `False` when the last pin failed (`PinFailed`), when nothing survives
  (`NotPinned`), or when some sections do not (`PartlyPinned`: exec is never
  pinned).
- **Restore checks.** A pinned state is restored only into the gadget image
  that pinned it (the manifest records the image digest) and only when its
  state maps carry the section's current prefix; otherwise the first start
  begins fresh, the old links keep judging until Settle, and the old layout's
  state pins are removed. Sets are ordered by the run that pinned them (the
  manifest's start time, from the boot clock, so a wall clock step cannot
  reorder them; a start later than the boot clock now, from a development
  build that wrote the wall clock, sorts as the oldest). Each old set keeps a link per hook; over 6 old sets
  (unreadable ones count too), the oldest sets go, but only a set whose
  cgroups a newer set all binds. Other sets stay, and if a hook then fills
  up, the new instance's attach is refused (`AttachCapacity`, fail closed).
  The newest readable set is never removed. The manifest's identity fields are written once; its slot list
  is rewritten after each publication, so the manifest map is not frozen.
- **A section that loses its last policy.** When no policy uses a section any
  more, it starts no instance; its old sets are reported (from their pinned
  bindings) until the first converged refresh, which removes them and resets
  the restored state.
- **Capacity.** While the adopted links and a new instance overlap, each hook
  carries two links of the section (within the budget of 8 per family per
  hook). A new instance refused with `E2BIG` is a typed `AttachCapacity`
  NotReady with backoff; it never drops the adopted state.
- **Cleanup.** With the feature off, or a section image unset, node-agent
  removes the pinned sets (and the section's `sbx1_*` state map pins) at
  start. A section whose image is set but which is unavailable (a failed host
  check) keeps its pinned sets: their links may still enforce, and its status
  says they are kept. At shutdown, node-agent removes them when its DaemonSet
  is gone or being deleted (an uninstall): no next node-agent would take them
  over. The sandbox closes first on SIGTERM, and the pins go as soon as the
  refresh loop stops, before the status writes and the gadget close (also
  when the loop does not stop within the shutdown time; a set that loop
  still pins after that stays until the node reboots); the running links
  stay held by the process until it exits. node-agent watches its own DaemonSet while it
  runs, and decides at the start of shutdown, before its RBAC can be removed:
  one fresh read (2 s at most), else the watched state. A DaemonSet recreated
  under the same name (another UID) keeps them. A DaemonSet rename, or a
  delete and recreate, counts as an uninstall for the old pods: they remove
  the pins, and the new pods report `RestartSurvival` `False` (each status
  read checks the set directories again). A rolling update, an eviction
  or a crash keeps the DaemonSet, so the pins stay. When neither the read nor
  the watch knows, the pins stay (fail closed).

Not covered:

- A pod that starts while node-agent is down is not enforced until node-agent
  is back and binds it. A restarted container of an existing pod is covered
  through the pinned pod cgroup bindings.
- Another loader of the same gadget on the node (a surge pod, `ig run`) shares
  the pinned state. This assumes one node-agent per node at a time, as a
  DaemonSet runs it.
- A node-agent killed (SIGKILL) during an uninstall before it decided cannot
  remove its pins: they stay until the node reboots or a node-agent with the
  feature off starts.
- Verdicts produced while node-agent is down are lost. After a restart, the
  old sets' programs still write their verdicts to ring buffers that no
  process reads: node-agent counts those denies (from each old set's counter
  map, by ID) as lost verdicts, so the policy shows `Degraded`
  (`VerdictsSuppressed`), and the note names the old sets' share. The count
  starts at node-agent's first read of each set: denies before it (while
  node-agent was down) are not counted. An old set whose counters cannot be
  read, or that is not validated, makes the lost-verdict count unknown
  (`VerdictLossUnknown`), never zero.
- The pinned sets kept for an unavailable section (a failed host check) are
  not pruned while the section stays unavailable: there is no owner to remove
  Audit or removed-policy cgroups from them. They keep the last enforced
  policy until the section is available again, or the node reboots.
- The exec section (the Inspektor Gadget engine) is not pinned.

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
For local tests, `sandboxPolicyDebugExport: true` (default false) registers a
`DebugReceiver` that logs each exported authorization, exec and section, as one
`sandbox authorization export` JSON line.

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

On a graceful stop the exporter outlives enforcement: `Service.Close` stops the
reconciliation loop, reports `AgentStopping` and withdraws enforcement first,
and only then stops the exporter (`VerdictExporter.Stop`). Verdicts reported
during withdrawal are still queued. Stopping refuses new verdicts at once
(counted as dropped) and delivers those already queued to the receivers for at
most `VerdictDrainTimeout` (2 s), within `Close`'s context; only verdicts still
queued at that deadline are counted as dropped, and `Close` then continues
(reporting the drain timeout to `OnError` when the deadline lost a verdict or
the exporter was still delivering at the deadline, never for a clean drain) and releases the runtime. A receiver
that never returns holds `Close` for at most that drain bound; the verdict
inside that receiver is counted only if the call ever returns. If `Close`
returns early with an error (its context ends while waiting for the
reconciliation loop, or withdrawal fails), the exporter keeps delivering until
a later `Close`. Hand-off to the queue stays nonblocking, so the drain
never delays enforcement or withdrawal. If the service never started the
exporter, `Close` counts any queued verdicts as dropped without waiting.
Cancelling `VerdictExporter.Run`'s own context (no `Stop`) likewise delivers
queued verdicts for at most `VerdictDrainTimeout` (2 s).

### Verdict telemetry metrics

Every 15 s the service exports its verdict counters through the agent's
metrics manager (OTel; with `OTEL_METRICS_EXPORTER=prometheus` each `.` becomes
`_`, so `node_agent.sandbox_policy.decode_errors.total` is scraped as
`node_agent_sandbox_policy_decode_errors_total`). They are observability only:
enforcement, fail-closed behavior and Ready/Degraded never read them.

| Metric | Labels | Meaning |
|---|---|---|
| `node_agent.sandbox_policy.exporter.events.total` | `result`: `enqueued`, `delivered`, `dropped`, `receiver_error`, `enrichment_error` | `Service.ExporterStats()`. `dropped` counts every verdict the exporter discards, which is exactly: one reported to a full queue, on an already-cancelled context, or after the exporter stopped; one still queued when the exporter is stopped before `Run` started; one still queued at the drain deadline; one whose pending enrichment is cut off by its context ending; and one with no receiver registered under `ExecAuthorizationEventType`. A failed receiver call (an error, a panic or an unsupported receiver type) counts as `receiver_error` instead. `delivered` counts receiver invocations, not kernel decisions. |
| `node_agent.sandbox_policy.kernel.events.total` | `result`: `submitted`, `lost`, `observation_error` | Kernel verdict-ring counters: the shared node's counters with the shared engine, else `Service.KernelEventStats()` owned plus retired totals. `lost` is a failed ring reservation. |
| `node_agent.sandbox_policy.section_exporter.events.total` | `result`: as `exporter.events.total` | `Service.SectionExporterStats()`: the privilege, network and file verdict queue. |
| `node_agent.sandbox_policy.section_kernel.events.total` | `section`: `privilege`, `network`, `file`; `result`: `denied`, `submitted`, `dropped`, `rate_limited`, `section_error`, `summary_overflow` | `Service.SectionVerdictStats()`, live plus retired instances. `dropped` (ring buffer full) and `rate_limited` are denies with no event. `summary_overflow` is the part of them with no summary record (summary map full). |
| `node_agent.sandbox_policy.decode_errors.total` | none | Verdict events dropped because they could not be read from the datasource or decoded against their generation's catalogue (`igbackend.ErrVerdictDecode`). Each one is also reported to `OnError`. |
| `node_agent.sandbox_policy.kernel.stats_complete` | none | 1 when every kernel counter was readable; 0 when some were not (an unreadable shared-node counter, or an unavailable owned or retired instance), so the kernel totals are a lower bound, or the kernel read was cut short (totals unknown for that pass). With the shared engine and no node started it is 1 (no kernel events exist). |

The counters are exported as growth above each counter's highest seen value:
a total that falls (an unreadable instance, a restarted shared node) adds
nothing, and only its growth past that value is counted later. For an engine
without a shared-node health source (per-instance counters), the wait for the
binding records' locks is bounded to 1 s
(best effort: a shared-engine `Health()` read and a per-instance counter read
are not interrupted); a read cut short exports no kernel counters for that pass
and sets `stats_complete` to 0. Every 15 s the counter pass briefly holds the
binding registry and record locks, so a binding change can wait for one pass:
enforcement is only delayed, never weakened.

When `dropped`, `receiver_error`, `enrichment_error`, decode errors, `lost`,
`observation_error`, or a section's `dropped` or `rate_limited` grow, the
service reports one `OnError` diagnostic
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

### Privilege, network and file authorizations

The node-wide section gadgets follow these steps. Each has its own event and
dispatch key: `PrivilegeVerdictEvent` (`privilegeAuthorization`),
`NetworkVerdictEvent` (`networkAuthorization`) and `FileVerdictEvent`
(`fileAuthorization`). They share `SectionVerdict` (decision, mode, `WouldDeny`,
rule, origins, policy set and matches, actor PID and comm); the operation facts
are in `PrivilegeTarget`, `NetworkTarget` and `FileTarget`. None of them
implements an observation interface: a denied connect is not a connection.

- The gadgets report denies only (enforced, or audit with `WouldDeny`).
- One verdict is one kernel check, not one syscall. A syscall the kernel
  checks twice gives two identical verdicts: an audited `setns` into a mount
  namespace checks CAP_SYS_ADMIN twice. Neither the gadget nor the exporter
  merges them; a consumer may merge identical verdicts of one task that
  arrive together.
- The binding comes from the event's cgroup: a container, or for privilege a
  pod cgroup (pod fields only). An unknown cgroup leaves it absent.
- The policy set comes from the slot table of the gadget instance that judged
  the call (the event's `generation` and `slot`), so a reload cannot attribute a
  verdict to the next revision. A rule names its policy. A section default
  names one only when the slot has one policy. The kernel keeps only the
  deciding rule, so `MatchesComplete` is false when the slot has more policies.
- Each policy in the set carries the revision that a container bind of that
  slot compiled. Pod plans and prepared plans have no revision, so they never
  replace a known one in the slot table; a slot that no container has bound
  yet reports an empty revision.
- Origins: presence comes from the gadget's origin id, so an explicit `""`
  stays `[""]` and no origin is `[]`. A default verdict carries the default
  origins of every policy that agrees with the merged default (per slot, and
  per access kind for file).
- Unknown today: executable path, parent PID, UID and network destination
  class.
- `SectionExporter` has its own bounded queue (1,024 entries) and worker, so
  a section deny burst never drops an exec verdict; both deliver to the same
  receivers. Section events are not enriched. Queue loss is in
  `Service.SectionExporterStats()`. Denies the kernel could not report (ring
  buffer full, rate limited) are in each gadget's verdict counters, exposed
  by `Service.SectionVerdictStats()`.

## Identity section

The `identity` section has no gadget. When node-agent parses a policy, it moves
each identity rule into the same policy's `file` or `network` section, with the
rule's own name, action, mode and origin:

- `path` / `pathClass` becomes a file rule with `access: [read]`;
- `imds: true` becomes an egress rule on the `imds` destination class;
- `envRead: true` becomes a file read rule on `/**/environ` with the file
  gadget's `otherProcess` flag: an open of another process's procfs `environ`
  file under any proc mount is judged, and a process can still read its own.
  Other ways to read another process's memory (`/proc/<pid>/mem`,
  `process_vm_readv`, ptrace) are not part of envRead.

A missing `file` or `network` section is added with an allow default, which does
not change the merged result. The paths of identity allow rules are subtracted
from the classes of identity deny rules, as `except` entries, so a provisioned
service-account token in `credentialStore` stays readable under every path alias.
Explicit deny paths are not subtracted (deny wins). A `deny` default and `false`
targets are reported in the `IdentityNotEnforced` condition. A `deny` default in
enforce mode runs in audit: it is listed under `degraded` (reason
`not-enforceable`) and the policy is not ready (`NotEnforceable`), as for an
enforce deny in the file and network sections.

A file `write` also covers a change of a file's access or modification time
(`touch`, `utimensat`, `futimens`) and of its extended attributes, set or
removed; a file capability (`security.capability`) and a POSIX ACL, set or
removed, are `chmod`. So a write deny on agent configuration in the
container's root file system also refuses `touch` and `setfattr` there, and the
verdict names it. On a volume (or a tmpfs) a time or extended attribute change
is not judged: its path cannot be resolved there, and failing closed would
break `touch`, `tar` and `cp -p` on every volume. Writes through `open` are
judged there as everywhere.

A file deny of `delete` or `chmod` without `rename` is reported in
`FileNotEnforced` (unless the rename default denies in enforce, after any
degrade): a rename can move a file out of the rule's paths first.

An enforce file deny that the file gadget cannot judge in full also makes the
policy not ready (`NotEnforceable`). A deny with `fsType`, `fromImage: false`,
or `fromImage` on a node whose overlay layout the gadget cannot read keeps its
paths without that predicate, so it over-blocks (reason `over-blocks`). A
`fromImage: true` deny with no path on such a node keeps no predicate at all:
it denies its access kinds on every file (`/**`), and `NotEnforceable` then
means the deny is wider than written, not that it is missing. A glob
the gadget cannot express is dropped, and the deny keeps its other globs. The
gadget does not judge `execMap`: an enforce deny of it (an `execMap`-only
rule, the `execMap` part of a rule, or an `execMap` default deny) makes the
policy not ready (`NotEnforceable`). A rule with other access kinds too has a
degraded entry (those kinds run). A rule or default that is only `execMap`
runs nothing (no verdict) and has no degraded entry: the status CRD requires an
effective mode there and accepts only `audit`, `enforce` and `tripwire`, which
would all claim coverage (any other value fails every status write of the
policy). It is listed in `FileNotEnforced`. An audit deny that the gadget
cannot judge is only reported in `FileNotEnforced`.

Path aliases: a deny rule matches every name the kernel can show for a file
(`/var/run` is `/run`, merged `/usr`, kubelet's `..<timestamp>` directory); its
excepts keep `/run` and `/usr` but match only the timestamp directory
(`..2*`); an allow rule matches only the timestamp directory, and identity's
provisioned allows also `/run`. See the file gadget
README.

## Verification boundary

Unit/race tests cover selection, reload bookkeeping, import refusal, status,
identity checks, queued-event ordering and public hook delivery. These are not
proof of kernel capabilities. Isolated IG tests have passed on Linux
7.0.0-31-generic x86_64 with BPF LSM enabled, including the 128th path, mixed modes,
strict scope, replacement/churn and reporting saturation; three repeat runs also
passed. They prove the expanded **legacy** backend, not the outstanding full
predicate integration. No arm64 or general-kernel support is claimed.

The separate advanced IG image has also passed isolated tests for staged argv from the new exec mm, actor/ancestor paths, effective
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

This is not broad distribution, compiler or runtime compatibility. Refusal or isolated component tests alone are
not sufficient completion evidence.

Node-agent pins a public IG pseudo-version (`go.mod`). The repository's merge
guard intentionally blocks this stacked dependency until IG #15 merges; re-pin
to its merged main revision before merging the consumer change. Do not bypass
that guard.

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

## Container admission details

CRI shared-memory admission authenticates sandbox metadata and its runtime-owned
OCI spec, then compares actual source/destination inode/device and whole TMPFS
mount roots. The protected host source retains nosuid/nodev/noexec. Some runc
binds drop these flags on the application mount. That case requires **all five
capability sets empty in both OCI and live proc status, no-new-privileges in both,
and exactly the canonical restrictive OCI device-policy baseline with no authored
allows**. Trusted runc still permits OCI default safe devices; this is not a
literal deny-every-device claim. Ordinary TMPFS execution is enforced by the gadget, not assumed impossible.

Read-only cgroup mounts must be actual cgroup v2 with readonly/nosuid/nodev/noexec
properties. Other mounts, capabilities, device-policy variants or runtime layouts
are refused, not exempted. Shared-memory metadata churn can invalidate the bounded
double-scan evidence; this conservative stable-snapshot boundary is not proof for
arbitrary active-IPC workloads. Runtime helpers remain subject to strict scope.

`Service.KernelEventStats(ctx)` exposes owned and retired kernel submitted,
ring-reservation-loss and observation-error counters. Retired totals survive
withdrawal; unavailable-instance counts and returned errors must be checked
before interpreting zero loss. These are separate from userspace
`ExporterStats()`. Early native gate refusals can occur before verdict
emission and are not counted as ring loss, so neither API promises complete
coverage of every operational denial.

Unreliable container snapshots use nonpublishing `Attest` for retained plans,
never `Replace`/`Resume`. Unsupported attestation reports protection unconfirmed.
Configuration-list failures freeze policy mutation and suppress confirmed-active
claims. Superseded uncommitted candidates must abort before another revision is
considered; already committed revisions cannot be rolled back.
