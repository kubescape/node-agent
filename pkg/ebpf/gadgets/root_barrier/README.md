# root_barrier

The root barrier of [`../common/root_barrier.h`](../common/root_barrier.h)
alone, for a live set of cgroups. Use it to test the barrier with Inspektor
Gadget alone, and as the example of how an enforcer includes the barrier.

An enforcer that checks a task's root from time to time (for example at each
exec) needs the barrier: without it, a task could change its root between two
checks. The barrier always denies, for every covered task (a task of a
binding that can enforce):

| Operation | LSM hook |
|---|---|
| chroot | `path_chroot` |
| pivot_root | `sb_pivotroot` |
| a new user namespace (clone, clone3, unshare) | `userns_create` (Linux 6.1+) |
| clone and clone3 with `CLONE_NEWNS` | `task_alloc` |
| unshare(`CLONE_NEWNS`); setns with type 0, `CLONE_NEWNS` or `CLONE_NEWUSER` | `capable` (`CAP_SYS_ADMIN`) |
| mount, move_mount, umount | `sb_mount`, `move_mount`, `sb_umount` |
| open_tree (clone), fsopen, fsconfig, fsmount, fspick, mount_setattr | `capable` (`CAP_SYS_ADMIN`) |
| any `CAP_SYS_ADMIN` use of a 32-bit task | `capable` |

Thread creation (glibc uses clone3) and setns into other namespace types stay
allowed. `docker exec` and `kubectl exec` join the cgroup namespace after the
mount namespace, inside the container cgroup.

## Coverage

The including gadget defines `ROOT_BARRIER_COVERED(task)`. Here it has the
shape of the enforce_exec `bindings` map, with two flags per binding:

- **Enforce.** Only a binding that can enforce is covered. An audit-only
  binding is never covered, so the barrier never blocks its tasks: audit-only
  stays strictly non-blocking.
- **Subtree.** Scope is exact by default (the strict binding scope of
  enforce_exec): only tasks in the bound cgroup itself are covered. Subtree is
  an explicit per-binding extension that the caller reports in its status: it
  covers descendant cgroups too. It needs the cgroup path (`Cgroup.Path`), and
  the bound cgroup must be at most 16 levels below the root (a container
  cgroup is usually 2 to 5 levels deep); the owner refuses a deeper one.
- **Outside an exact scope.** A task of an enforcing binding without Subtree
  that is in a descendant cgroup (it moved into a child cgroup it created, or
  `clone3(CLONE_INTO_CGROUP)` started it there) does not escape: the predicate
  returns a Strict fault, so the barrier denies and counts it in
  `root_barrier_faults` (`Owner.Faults`).

A task in the binding's runtime mount namespace (the container runtime's work
in the cgroup before it joins the container) is not covered. Tasks that ran
before the gadget are covered. The root cgroup cannot be bound.

## Ready

The native operator ([`runtime`](runtime)) reports Ready only after
`rootbarrier.Verify`:

1. "bpf" is in the kernel's active LSM list.
2. Each barrier program has a live LSM link to its hook. The programs of this
   instance are found through the instance's `root_barrier_counters` map.
3. A self-test covers one thread of the process through `root_barrier_probe`
   and checks that setns, chroot, pivot_root, mount, clone with `CLONE_NEWNS`
   and clone with `CLONE_NEWUSER` fail with EPERM, and that the barrier marked
   each operation in the probe entry (so a denial by another layer does not
   count). The thread is matched in its own PID namespace. Each probe has no
   effect when the barrier does not deny, and self-test denials send no event.

A failure refuses activation when an initial binding enforces. A later binding
that enforces retries the verification (`rootbarrier.VerifyMaps`) and is
refused while it fails. Audit-only bindings never depend on the barrier, but
`Owner.Health` returns the failure, so the caller reports a degraded or
NotReady condition instead of a silent Ready.

The barrier keeps no policy state: its maps are the denial and fault counters
and the probe. In a gadget with one long-lived collection, the barrier links
stay with that collection and are never detached when a binding or a policy is
published; a publication changes only the state the predicate reads. This
standalone gadget is the reference for the header only.

## Events

`denial`: one event per denied operation of a covered task, with the cgroup, the process and
thread ids, the command name, the operation (`op_raw`, enum `root_barrier_op`)
and the clone flags, setns type or capability. When the 4 KiB ring buffer is
full, the event is dropped and counted in `denial_drops` (`Owner.Drops`); the
denial still happens.

## Test

`runtime/runtime_kernel_test.go` (build tag `root_barrier_kernel`) starts a
disposable Docker container and checks the denials, glibc threads, a task that
ran before the gadget, a task moved into a child cgroup, an audit-only binding
(never blocked, also with a missing hook), an exact Strict binding (a child
cgroup is a Strict fault, denied and counted), a subtree binding (needs a
path, covers a child cgroup), a reload with two instances, a BPF LSM denial that runs before the barrier (kept unchanged), and a startup with a
missing hook. See the file header for the environment variables.
