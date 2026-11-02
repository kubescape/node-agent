# enforce_privilege

Container privilege enforcement with BPF LSM, no seccomp. It enforces the
`privilege` section of a sandbox policy: namespace creation and joining, mounts,
`pivot_root`/`chroot`, capabilities, ptrace, kernel modules, `bpf`,
`perf_event_open`, keys, `io_uring_setup`, `userfaultfd`, `mknod`,
`setuid`/`setgid` and `capset`.

The gadget is built on the [common enforcement library](../common/README.md).
One instance runs per node:

- A **slot** is one combination of privilege policies; containers with the same
  combination share it. Limits per node: 1024 containers, 64 slots, 512 policy
  map entries per slot, 16384 in total.
- Binding or unbinding a container is a live write to the `bindings` map.
- The policy map is frozen per instance. A combination the running instance
  does not have (a new or edited policy) needs a new instance: the owner starts
  one with every slot in use and every container bound, and then stops the old
  one, so both enforce during the overlap (the sandbox policy controller does
  this).
- An owner can create a slot before a container starts (for example when its
  pod is scheduled to the node), so the container binds with a live write.
- Several policies on one container merge as the SandboxPolicy design says: the
  union of rules (explicit deny > allow > default, each rule with its own name,
  origin and mode); a default is deny if any policy denies, with the strictest
  mode among the policies that agree. One addition to the design: a monitoring
  (audit) deny rule never weakens another policy's enforce deny, including its
  enforce default deny. An explicit allow still beats another policy's default
  deny.

`policy/` compiles the `privilege` section of one or more policies;
`runtime/` is the native owner a controller drives.

Requires cgroup v2, kernel BTF and BPF LSM enabled (`bpf` in
`/sys/kernel/security/lsm`). Linux 6.1 or later (the `userns_create` hook;
`io_uring_setup` reaches `inode_init_security_anon` from 5.16).
Build the image with `make build` (it sets `IG_SOURCE_PATH`, see the library
README).

## Policy

The `privilege` section of a SandboxPolicy, for example:

```yaml
spec:
  mode: enforce              # audit | enforce | off
  privilege:
    default: allow           # applies to syscall and mountFsType targets
    rules:
      - name: no-new-namespaces
        target: {syscall: [unshare, clone, clone3, setns], flags: [CLONE_NEWUSER, CLONE_NEWNS]}
        action: deny
        origin: catalog/G1
      - name: no-proc-mount
        target: {mountFsType: [proc, sysfs]}
        action: deny
      - name: audit-sys-admin
        target: {capability: [SYS_ADMIN]}
        action: deny
        mode: audit
```

- A rule targets exactly one kind: `syscall` (optionally with `flags` for
  `unshare`, `setns`, `clone`, `clone3`), `capability` (short names such as
  `SYS_ADMIN`) or `mountFsType`.
- Resolution: an explicit deny beats an allow, an allow beats the default,
  independent of rule order. Each rule has its own mode.
- Capability checks have no default; only explicit capability rules apply.
- A `default: deny` also denies `setuid`/`setgid` (package managers drop
  privileges), implicit kernel module loads (judged as `init_module`, for
  example an `iptables` match module) and new superblocks of any filesystem
  type. Allow what the workload needs.
- `actor`, `except` and `pathClass` are not supported yet.

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
- **Scope.** A bound cgroup also covers up to 31 levels of child cgroups.
- **Capabilities.** A `capable()` call is judged only when the task uses its own
  credentials (overlayfs copy-up uses the mounter's) and the call is not a
  no-audit probe.
- **Syscalls without their own hook** (`unshare` without a user namespace,
  `setns`, `open_tree`, `fsopen`, `fsmount`, `fspick`, `mount_setattr`) are
  judged at their `CAP_SYS_ADMIN` check by syscall number. For a 32-bit
  (compat) task the number is not mapped, so these checks fail closed: every
  candidate syscall rule applies.
- **Deny** returns `-EPERM` from the LSM hook, before the side effect.

## Known limits

- **Failed arming mark.** If the kernel cannot allocate task storage (memory
  pressure), the task stays unarmed and is not judged until its next exec. The
  failure is counted in `counters` slot 4. A later check cannot tell such a
  task apart from the runtime's own setup, so it is not retried.
- **No-audit capability checks** (`CAP_OPT_NOAUDIT`) are not judged. They are
  kernel probes (for example the overcommit check); judging them would deny
  normal work in every bound container. One of them grants write access to
  `/proc/sys/kernel/ns_last_pid`, which the privilege section does not cover.

## Maps and events

| Map | Content |
|---|---|
| `policy` | frozen hash: `{slot, kind, id, qual, name}` → `{rank, rule_id, origin_id}`; each slot's META entry holds generation and mode (`privilege_policy.h`) |
| `bindings`, `armed_tasks`, `counters` | from the common library |

The `verdict` datasource shares `generation`, `cgroup`, `deny`, `mode` and
`host_pid` with enforce_exec and adds `rule_id`, `origin_id`, `is_default`,
`comm`, `hook`, `syscall`, `flags`, `capability`, `fstype` and `slot`. Rule and origin
names are in the owner's compiled policy (`RuleNames`, `Origins`). Reporting is
limited to 100 events per CPU per second; enforcement is never throttled.

