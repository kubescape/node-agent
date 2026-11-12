# enforce_privilege

Container privilege enforcement with BPF LSM, no seccomp. It enforces a
privilege policy: namespace creation and joining, mounts, `pivot_root`/`chroot`,
capabilities, ptrace, kernel modules, `bpf`, `perf_event_open`, keys,
`io_uring_setup`, `userfaultfd`, `mknod`, `setuid`/`setgid` and `capset`.

The gadget is built on the [common enforcement library](../common/README.md).
It depends only on Inspektor Gadget and that library. One instance runs per
node:

- A **slot** is one combination of policy documents; containers with the same
  combination share it. Limits per node: 1024 containers, 64 slots, 512 policy
  map entries per slot, 16384 in total.
- Binding or unbinding a container is a live write to the `sbx1_priv_bindings`
  map. The state maps are pinned by name (`../common/pin.h`, prefix
  `sbx1_priv_`), so the next load re-opens them.
- The policy map is keyed by storage index (`../common/slots.h`): each slot
  has two buffers. The runtime publishes each slot of its compiled policy when
  the instance starts (`Publications`, META entry last). A publication into a
  running instance writes the inactive buffer and flips the slot in one map
  write; the old buffer is deleted after a quarantine. Programs cannot write
  the map (`BPF_F_RDONLY_PROG`); a published buffer is never changed.
- An owner can create a slot before a container starts, so the container binds
  with a live write.

`policy/` parses and compiles policy documents; `runtime/` is the native
operator an owner drives with `runtime.WithConfig` and `runtime.GetBindings`.

Requires cgroup v2, kernel BTF and BPF LSM enabled (`bpf` in
`/sys/kernel/security/lsm`). Linux 6.1 or later (the `userns_create` hook;
`io_uring_setup` reaches `inode_init_security_anon` from 5.16).
Build the image with `make build` (it sets `IG_SOURCE_PATH`, see the library
README).

## Policy

A policy document (YAML or JSON), parsed with `policy.Parse`. Full example:
[examples/policy.yaml](examples/policy.yaml).

```yaml
version: 1
name: example                # qualifies rule names in events
policy:
  mode: enforce              # audit | enforce | off
  privilege:
    default: allow           # default for syscall and mountFsType targets
    rules:
      - name: no-new-namespaces
        target: {syscall: [unshare, clone, clone3, setns], flags: [CLONE_NEWUSER, CLONE_NEWNS]}
        action: deny
      - name: no-proc-mount
        target: {mountFsType: [proc, sysfs]}
        action: deny
      - name: watch-sys-admin
        target: {capability: [SYS_ADMIN]}
        action: deny
        mode: audit          # a rule may override the document mode
```

- A rule targets exactly one kind: `syscall` (optionally with `flags` for
  `unshare`, `setns`, `clone`, `clone3`; required for `clone` and `clone3`,
  because a plain fork is never judged), `capability` (short names such as
  `SYS_ADMIN`) or `mountFsType`.
- Resolution: an explicit deny beats an allow, an allow beats the default,
  independent of rule order. Each rule has its own mode. Each namespace flag of
  a call resolves on its own.
- Capability checks have no default; only explicit capability rules apply.
- `mountFsType` judges the creation of a new filesystem instance (a new
  superblock, from `mount(2)` or the new mount API). Bind mounts and remounts
  of an existing one are judged only by the `mount` syscall rule.
- A `default: deny` also denies `setuid`/`setgid` (package managers drop
  privileges), implicit kernel module loads (judged as `init_module`, for
  example an `iptables` match module) and new superblocks of any filesystem
  type. Allow what the workload needs.
- **Several documents in one slot** combine so that the most limiting result
  wins: the union of rules (explicit deny > allow > default, each rule with its
  own name, origin and mode); a default is deny if any document denies, with the
  strictest mode among the documents that agree; a monitoring (audit) deny rule
  never weakens another document's enforce deny, including its enforce default
  deny; an explicit allow still beats another document's default deny. The
  rule and its test vectors are shared with other sections:
  [merge contract](../common/merge/CONTRACT.md).

## How it decides

- **Arming.** Only armed tasks are judged. A task is armed when it executes a
  program outside the container runtime's mount namespace; children inherit the
  mark. So runc's own setup (namespaces, mounts, `pivot_root`, `setns` for
  `exec`) is never blocked, and `docker run` / `docker exec` keep working.
  OCI `createContainer` and `startContainer` hooks are not armed only under
  an owner-admitted binding flag, `Binding.RuntimeHelpers` (needs `Subtree`):
  the owner sets it on a parent cgroup bound before its containers start,
  never on a container binding. Under that flag a task is not armed at exec
  when its parent is unarmed, outside the runtime mount namespace, and in the
  same mount namespace and cgroup (runc init forks the hooks inside the
  container). Each exempted exec is counted (`Bindings.ArmingWitness`,
  `ExemptExecs`). Without the flag there is no helper exemption, as in
  enforce_exec's Strict profile.
  When a container is bound, the owner also arms the tasks that already run in
  it (pidfd writes to `armed_tasks`). The runtime mount namespace is the
  `host-mntns-id` gadget parameter; the owner sets it to the mount namespace of
  PID 1 as it sees it (in kind, the node container's). When it is 0, the
  program uses the global init task's.
- **Lost arming.** The kernel can fail to allocate a task's mark (memory
  pressure). When an armed task forks and the child's mark fails, a Strict
  binding (its slot has any enforce entry) refuses the fork (`-ENOMEM`): an
  unmarked child would escape every rule. Audit never blocks, even on a fault:
  an Audit binding, or an unbound cgroup, allows the fork. When that fork is a
  clone into another cgroup (`CLONE_INTO_CGROUP`), the child can start in a
  Strict cgroup, so it counts a node fault (`Bindings.ArmingWitness`,
  `NodeFaults`) that the owner reports against every Strict binding. A new thread of an armed group leader is
  covered through the leader, so it is never refused. An unarmed parent (for
  example a runtime helper) is out of scope, not a failure. Every failed mark that
  leaves a task unarmed is counted in `counters` slot 4. A failed mark of a new
  thread is not counted: the thread is covered through its leader, and it is
  marked at its own exec. Moving a container to another slot arms its
  running tasks again.
- **Slot faults.** A failed mark in a Strict binding (a refused fork, or a
  lost mark at exec, which cannot be refused) is also counted per slot in
  `arming_faults`. The owner reads it with `Bindings.SlotFaults`: a nonzero
  count means the slot's protection is not confirmed. A new publication of a
  slot starts at zero; `Bindings.Heal` arms the slot's running tasks again and
  restarts the count, without a reload. Audit-only faults do not count there.
- **Missing slot policy.** A bound cgroup whose slot has no META entry is a
  structural fault, not an unbound task. A Strict binding then denies every
  judged check (`-EPERM`) and counts a slot fault in `arming_faults`; an
  Audit binding allows. Both count in `counters` slot 4. The binding carries its class
  (`BINDING_STRICT`), so the class is known without the policy. The owner sets
  it from the slot's META mode.
- **Fault verdicts.** A structural fault of an armed task, and a lost mark in
  a Strict binding, also send a verdict with hook `fault` (`fault_raw`:
  `structural` or `tracking`), the slot and the slot's generation (0 when the
  slot has no policy). It is an enforce verdict when the hook denies and an
  audit verdict when it allows (an Audit binding, or an exec, which cannot be
  refused). A lost mark in an Audit binding sends none. The controller exports
  it with reason `operational_error`, as the file section does.
- **Scope.** A binding covers its exact cgroup, as in enforce_exec. A binding
  with `Subtree` (`BINDING_SUBTREE`) also covers its descendant cgroups at any
  depth; the owner sets it only for a parent cgroup bound before its containers
  start, and reports it. A subtree binding must be at cgroup level 31 or less
  (the controller refuses a deeper one; levels are counted in the owner's
  cgroup namespace, the kernel counts from the host root). The task's own
  binding wins, then the nearest parent that is a subtree binding or a Strict
  binding. A task in a child cgroup of a Strict exact binding (a workload that
  moved itself there) is outside the binding's scope but is not left
  unjudged: every judged check denies, as a structural fault with a slot
  fault.
- **Capabilities.** A `capable()` call is judged only when the task uses its own
  credentials (overlayfs copy-up uses the mounter's) and the call is not a
  no-audit probe.
- **Syscalls without their own hook** (`unshare` without a user namespace,
  `setns`, `open_tree`, `fsopen`, `fsmount`, `fspick`, `mount_setattr`) are
  judged at their `CAP_SYS_ADMIN` check by syscall number. For a 32-bit
  (compat) task the number is not mapped, so these checks fail closed: every
  candidate syscall rule applies. The same holds for `mknod`: for a compat
  task every `inode_mknod` call is judged as `mknod`, including a unix socket
  `bind(2)`, so a `mknod` deny or a default deny also refuses that bind.
- **Deny** returns `-EPERM` from the LSM hook, before the side effect.

## Known limits

- **Runtime helpers are trusted under `RuntimeHelpers`.** In a binding with the
  flag, a task forked by an unarmed task inside the container (an OCI hook, or
  a process a hook leaves behind) is not judged, and neither are its children.
  A workload task whose exec mark failed (memory pressure) is also an unarmed
  parent; in an Audit binding that loss counts no slot fault, and its exec'd
  children are then exempt too. `ExemptExecs` makes every exemption visible. Only the runtime or a host root process can
  create such a task. This was verified with runc, which execs the workload
  and `exec` commands from runc init itself; a runtime that forks them from a
  helper inside the container would leave them unjudged. A binding (or
  owner restart) between `runc create` and `runc start` arms runc init, and
  the startContainer hooks it then runs are judged.

- **Lost mark at exec.** The exec hook cannot fail the exec, so a task whose
  mark fails there stays unarmed until its next exec. In an enforcing slot this
  is a tracking fault (see above). A later check cannot tell such a task apart
  from the runtime's own setup, so the gadget does not retry it; a new instance
  arms it again.
- **Fault injection.** The `arming-fail-fork-marks` parameter makes every child
  mark fail at fork, and `policy-fail-headers` makes every slot miss its META
  entry. They exist for tests (`runtime/runtime_kernel_test.go`); owners do
  not set them.
- **Kernels older than 6.1** are not supported yet.
- **Leaving the bound cgroup.** A task that can write to a cgroup outside its
  binding's subtree (its `cgroup.procs`, or `clone3` with `CLONE_INTO_CGROUP`)
  runs there without this binding's policy. A child cgroup of a Strict binding
  denies (see Scope); a cgroup elsewhere needs write access to the host cgroup
  tree, which a normal container does not have. A `CLONE_INTO_CGROUP` clone is
  refused only when the child's mark fails in a Strict binding.
- **Containers that move into their own child cgroup.** docker:dind moves its
  processes into a child cgroup at start, and systemd images move PID 1 into
  `init.scope`. Under a Strict exact binding every judged check of those tasks
  is denied (see Scope), so such a container does not run. It needs an
  explicit `Subtree` binding.
- **Node faults stay counted.** `NodeFaults` only grows in one instance, so
  one lost `CLONE_INTO_CGROUP` mark marks every Strict binding unconfirmed.
  The owner recovers with a new instance, which starts at zero and arms the
  running tasks again.
- **No-audit capability checks** (`CAP_OPT_NOAUDIT`) are excluded from
  capability enforcement. Most are kernel probes (for example the overcommit
  check), and judging them would deny normal work in every bound container. Some
  also grant access (in current kernels, writing the pid namespace's `pid_max`),
  so `capability` rules do not cover every `CAP_SYS_ADMIN` use.

## Using it outside this repository

- The gadget and `../common` depend only on Inspektor Gadget, the libraries it
  uses, and the `enforce_exec` types of the Inspektor Gadget fork. A guard test
  (`common/enforcement/portability_test.go`) keeps it that way.
- A Go program drives it: `runtime.WithConfig` with a compiled policy, then
  `runtime.GetBindings` to bind containers (see `runtime/runtime_kernel_test.go`).
  There is no `ig` command for it yet; `ig run` alone fails because the policy
  comes from the owner, not from gadget parameters.
- To move it into Inspektor Gadget: rewrite the import paths, drop the
  per-gadget `Makefile` (its `REPO_ROOT` is this repository's depth) and add the
  gadget to the central gadget list, which already sets `IG_SOURCE_PATH`.

## Maps and events

| Map | Content |
|---|---|
| `sbx1_priv_policy` | pinned read-only hash (32768 entries, two buffers per slot): `{storage, kind, id, qual, name}` → `{rank, rule_id, origin_id}`; each publication's META entry holds generation and mode (`privilege_policy.h`) |
| `sbx1_priv_bindings`, `sbx1_priv_slot_state`, `sbx1_priv_armed_tasks`, `sbx1_priv_arming_faults`, `sbx1_priv_arming_witness` (pinned), `counters` | from the common library; a binding value is `{slot, flags}` (`BINDING_SUBTREE`, `BINDING_STRICT`, `BINDING_RUNTIME_HELPERS`) |

The `verdict` datasource shares `generation`, `cgroup`, `deny`, `mode` and
`host_pid` with enforce_exec and adds `rule_id`, `origin_id`, `is_default`,
`comm`, `hook`, `syscall`, `flags`, `capability`, `fstype` and `slot`. When a
document's default deny strengthens another document's audit rule on the same
key, the event names the rule `default` with `is_default` false. Rule and origin
names are in the owner's compiled policy (`RuleNames`, `Origins`). Origin id 0
means no origin; an explicit empty origin has its own id. A default verdict
(rule `default`) takes its origins from `DefaultOrigins[slot]`: the default
origins of the documents that agree with the slot's merged default. Reporting is
limited to 100 events per CPU per second; enforcement is never throttled.

A verdict is one kernel check, not one syscall. A syscall that checks the same
capability twice gives two identical verdicts in audit mode, because audit lets
the first check pass: `setns` checks `CAP_SYS_ADMIN` against the namespace's
user namespace and against the caller's, so an audited `setns` gives two. In
enforce mode the first deny stops the syscall, so it gives one. The `counters`
count checks the same way. A consumer that needs one event per syscall can
merge identical verdicts of one task that arrive together.

