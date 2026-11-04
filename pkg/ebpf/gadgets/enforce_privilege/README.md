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
- Binding or unbinding a container is a live write to the `bindings` map.
- The policy map is frozen per instance. A combination the running instance
  does not have (a new or edited policy) needs a new instance: the owner starts
  one with every slot in use and every container bound, and then stops the old
  one, so both enforce during the overlap. This whole-instance replacement is a
  staging choice: the owner hides it behind its backend interface, so a later
  in-place policy update can replace it.
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
  When a container is bound, the owner also arms the tasks that already run in
  it (pidfd writes to `armed_tasks`). The runtime mount namespace is the
  `host-mntns-id` gadget parameter; the owner sets it to the mount namespace of
  PID 1 as it sees it (in kind, the node container's). When it is 0, the
  program uses the global init task's.
- **Lost arming.** The kernel can fail to allocate a task's mark (memory
  pressure). When an armed task forks and the child's mark fails, an enforcing
  slot (one with any enforce entry) refuses the fork (`-ENOMEM`): an unmarked
  child would escape every rule. A clone into another cgroup
  (`CLONE_INTO_CGROUP`) is refused the same way. An audit-only slot, or an
  unbound cgroup, allows the fork. A new thread of an armed group leader is
  covered through the leader, so it is never refused. An unarmed parent (for
  example a runtime helper) is out of scope, not a failure. Every failed mark that
  leaves a task unarmed is counted in `counters` slot 4. A failed mark of a new
  thread is not counted: the thread is covered through its leader, and it is
  marked at its own exec. Moving a container to another slot arms its
  running tasks again.
- **Tracking faults.** A failed mark in an enforcing slot (a refused fork, or a
  lost mark at exec, which cannot be refused) is also counted per slot in
  `arming_faults`. The owner reads it with `Bindings.SlotFaults`: a nonzero
  count means the slot's protection is not confirmed. A new instance starts at
  zero and arms the running tasks again. Audit-only faults do not count there.
- **Scope.** A bound cgroup also covers up to 31 levels of child cgroups. This is
  by design and differs from enforce_exec, which binds the exact cgroup only.
  The nearest bound cgroup decides. So an owner can bind a parent cgroup (for
  example the cgroup of a group of containers) before they start, with
  `SkipArming`, and a container is judged from its first exec. The tasks
  already in the parent are not armed, also not at a slot move or in a new
  instance, because a runtime helper can be there during its setup.
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

- **Parent bindings.** A bound parent cgroup also judges the armed tasks of
  its child cgroups that have no binding of their own: OCI `createContainer`
  and `startContainer` hooks (runc runs them in the container mount
  namespace before the workload), and an infrastructure (pause) process. A
  new instance does not arm the tasks that run only under a parent binding;
  they are judged again when their own cgroup is bound or at their next exec.

- **Lost mark at exec.** The exec hook cannot fail the exec, so a task whose
  mark fails there stays unarmed until its next exec. In an enforcing slot this
  is a tracking fault (see above). A later check cannot tell such a task apart
  from the runtime's own setup, so the gadget does not retry it; a new instance
  arms it again.
- **Fault injection.** The `arming-fail-fork-marks` parameter makes every child
  mark fail at fork. It exists for tests (`runtime/runtime_kernel_test.go`);
  owners do not set it.
- **Kernels older than 6.1** are not supported yet.
- **Leaving the bound cgroup subtree.** A task that can write to a cgroup
  outside its bound subtree (its `cgroup.procs`, or `clone3` with
  `CLONE_INTO_CGROUP`) runs there without the policy. This needs write access
  to the host cgroup tree, which a normal container does not have. A
  `CLONE_INTO_CGROUP` clone is refused only when the child's mark fails.
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
| `policy` | frozen hash: `{slot, kind, id, qual, name}` → `{rank, rule_id, origin_id}`; each slot's META entry holds generation and mode (`privilege_policy.h`) |
| `bindings`, `armed_tasks`, `arming_faults`, `counters` | from the common library |

The `verdict` datasource shares `generation`, `cgroup`, `deny`, `mode` and
`host_pid` with enforce_exec and adds `rule_id`, `origin_id`, `is_default`,
`comm`, `hook`, `syscall`, `flags`, `capability`, `fstype` and `slot`. When a
document's default deny strengthens another document's audit rule on the same
key, the event names the rule `default` with `is_default` false. Rule and origin
names are in the owner's compiled policy (`RuleNames`, `Origins`). Reporting is
limited to 100 events per CPU per second; enforcement is never throttled.

