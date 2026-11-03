# root_barrier

The root barrier of [`../common/root_barrier.h`](../common/root_barrier.h)
alone, for a live set of cgroups. Use it to test the barrier with Inspektor
Gadget alone, and as the example of how an enforcer includes the barrier.

An enforcer that checks a task's root from time to time (for example at each
exec) needs the barrier: without it, a task could change its root between two
checks. The barrier always denies, for every covered task:

| Operation | LSM hook |
|---|---|
| chroot | `path_chroot` |
| pivot_root | `sb_pivotroot` |
| a new user namespace (clone, clone3, unshare) | `userns_create` (Linux 6.1+) |
| clone and clone3 with `CLONE_NEWNS` | `task_alloc` |
| unshare(`CLONE_NEWNS`); setns with type 0, `CLONE_NEWNS` or `CLONE_NEWUSER` | `capable` (`CAP_SYS_ADMIN`) |
| mount, move_mount, umount | `sb_mount`, `move_mount`, `sb_umount` |
| open_tree (clone), fsopen, fsmount, fspick, mount_setattr | `capable` (`CAP_SYS_ADMIN`) |
| any `CAP_SYS_ADMIN` use of a 32-bit task | `capable` |

Thread creation (glibc uses clone3) and setns into other namespace types stay
allowed. `docker exec` and `kubectl exec` join the cgroup namespace after the
mount namespace, inside the container cgroup.

## Coverage

The including gadget defines `ROOT_BARRIER_COVERED(task)`. Here it has the
shape of the enforce_exec `bindings` map: a task is covered when its cgroup is
in `covered_cgroups`, unless the value is a mount namespace inode and the task
runs in that namespace (the container runtime's work in the cgroup before it
joins the container). A child starts in its parent's cgroup, so descendants and
tasks that ran before the gadget are covered too.

## Ready

The native operator ([`runtime`](runtime)) reports Ready only after
`rootbarrier.Verify`:

1. "bpf" is in the kernel's active LSM list.
2. Each barrier program has a live LSM link to its hook. The programs of this
   instance are found through the instance's `root_barrier_counters` map.
3. A self-test covers one thread of the process through `root_barrier_probe`
   and checks that setns, chroot, pivot_root, mount, clone with `CLONE_NEWNS`
   and clone with `CLONE_NEWUSER` fail with EPERM and are counted by the
   barrier. Each probe has no effect when the barrier does not deny.

A failure refuses activation. Keep the old instance until the replacement is
Ready, so that a reload has no gap.

## Events

`denial`: one event per denied operation, with the cgroup, the process and
thread ids, the command name, the operation (`op_raw`, enum `root_barrier_op`)
and the clone flags, setns type or capability.

## Test

`runtime/runtime_kernel_test.go` (build tag `root_barrier_kernel`) starts a
disposable Docker container and checks the denials, glibc threads, a task that
ran before the gadget, a reload with two instances, and a startup with a
missing hook. See the file header for the environment variables.
