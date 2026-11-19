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
  covers descendant cgroups too. An enforcing or subtree binding needs its
  cgroup path (`Cgroup.Path`, checked against the id), and must be at most 16
  levels below the root (a container cgroup is usually 2 to 5 levels deep);
  the owner refuses a deeper one, whose moved tasks the program could not see.
  The nearest bound parent decides: an audit-only one covers nothing. An exact
  audit-only binding is not a parent: its scope is its own cgroup, so it does
  not end the scope of an enforcing subtree binding above it. A task below it
  is judged by the binding above, at any depth (the owner does not check the
  level of an exact audit-only binding, and the walk skips it).
  **Precedence:** for an exact audit-only binding inside an enforcing subtree
  binding, the tasks of the audit cgroup itself are Audit (the task's own
  binding decides, so they are never blocked), and the tasks below it are
  Strict (the subtree binding above covers them). The kernel test "an exact
  Audit binding below a Strict subtree binding does not end its scope" checks
  both.
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
that enforces is refused while the verification fails. Audit-only bindings
never depend on the barrier, but `Owner.Health` returns the failure, so the
caller reports a degraded or NotReady condition instead of a silent Ready.

`Cover` (for an enforcing binding) and `Owner.Health` retry a failed
verification (`rootbarrier.VerifyMaps`) through one helper: one retry at a
time, at most every 10 seconds; in between, the last error stays.

When a verification passes, the owner reads the kernel IDs of the barrier
programs (`rootbarrier.ProgramIDs`, which returns the hooks with `Hook.ID`
set). `Owner.Health` then runs `rootbarrier.Attest` with these hooks, so
every `rb_*` program is matched by its program ID, not only its name, and
must still have a live LSM link to its hook. The attestation walks every link
on the host, so it runs at most every 10 seconds, one at a time; a call in
between returns the last result, and a passing verification makes the next
call attest again. A detached link is reported within 10 seconds. A missing
link is an error that names the program and the hook, and refuses enforcing
bindings until a retried verification passes.

The barrier keeps no policy state: its maps are the denial and fault counters
and the probe. In a gadget with one long-lived collection, the barrier links
stay with that collection and are never detached when a binding or a policy is
published; a publication changes only the state the predicate reads. This
standalone gadget is the reference for the header only.

## Coverage lifetime

Seccomp applies from the container's first instruction and survives an agent
restart. The barrier does not. It covers a task only while both hold:

- the task's cgroup is covered: between `Cover` and `Uncover`, so not before
  the binding (a container that starts before its binding);
- the barrier's links exist: they are not pinned, so they end with the
  gadget instance (an agent restart, a crash, a replacement).

A task can change its root (chroot, pivot_root, a new mount namespace) in a
gap. So an enforcer that relies on the barrier must check the task's root
again after every `Cover` and after every barrier gap (a new instance, an
agent restart) before it trusts the root it checked before. Pinning the
barrier's links would close the restart gap; it is not done here.

## Attach capacity

The barrier adds one BPF LSM link on each of its 8 hooks: `path_chroot`,
`sb_pivotroot`, `userns_create`, `task_alloc`, `capable`, `sb_mount`,
`move_mount` and `sb_umount`. Every gadget that includes the header adds its
own link on each of the 8 hooks: a separate `rb_*` program, or its own program
that calls the hook body (`ROOT_BARRIER_NO_<NAME>_PROGRAM`), which is then the
only link of that gadget on the hook.

The kernel holds a fixed number of links per trampoline, shared by fentry,
fexit and BPF LSM programs (an LSM hook `X` uses `bpf_lsm_X`), and refuses one
more with `E2BIG`. Measured on AL2023 6.12.113-138.209 and 6.18.56-125.164: 38
links per trampoline. The budget: each family (one gadget) uses at most 8
links per hook, and 8 links per hook stay free for third parties, so all
families together use at most 30 links on a hook.

Per hook, with this standalone gadget and N gadgets that include the barrier:

| | Barrier links on each of the 8 hooks |
|---|---|
| this standalone gadget | 1 (2 while a reload runs the old and the new instance together) |
| each including gadget | 1 (its `rb_*` program, or its own program that calls the body) |
| total | N + 1 (N + 2 during a reload of this gadget) |

An including gadget counts the barrier link in its own per-hook budget of 8,
together with its own programs on the same hook. On a hook that the gadget
also uses for itself (for example `task_alloc` or `capable`), the inline path
adds no second link. Other BPF consumers on the node can already use links on
`capable` and `sb_mount`, so these links and the third-party reserve must fit
in the 38 on every hook: N + 1 + (the gadgets' own links on the hook) + (links
already used on the node) + 8 ≤ 38.

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
path, covers a child cgroup), a reload with two instances, a BPF LSM denial
that runs before the barrier (kept unchanged), and a startup with a missing
hook. It also checks `Owner.Health` (the link check by program ID), an exact
audit-only binding below a Strict subtree binding (a task below it stays
denied; at a shallow level and deeper than the parent walk), and the
`task_alloc` order with a stand-in program that allocates task storage: when
the barrier runs first, it denies before any allocation; when it runs second,
it denies after the allocation and `task_free` releases the storage (the
allocation and release counters balance). See the file header for the
environment variables.

`common/rootbarrier/kerneltest` is the fork's opt-in kernel test of the header
and its Go attestation, copied unchanged (the fork drift check compares it):
it compiles its own test programs, then checks `ProgramIDs` and `Attest` by
program ID, the `task_alloc` composition and compat tasks. Run it as root on a
disposable BPF LSM node with clang, bpftool and the libbpf headers, with
`IG_ROOT_BARRIER_KERNEL_TEST=1`.
