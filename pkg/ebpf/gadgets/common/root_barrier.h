// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Kubescape Authors

// Root barrier: BPF LSM programs that stop a covered task from changing its
// root or its mount namespace, and from changing the mount tree under its root.
// An enforcer that checks a task's root from time to time (for example at each
// exec) needs this, because the task could otherwise change its root between
// two checks.
//
// The barrier always denies for a covered task. It has no mode and no policy
// map: it is an invariant of the including gadget, not a rule. The predicate
// must cover only tasks of bindings that can enforce: an audit-only binding is
// strictly non-blocking, so the barrier must never judge its tasks.
//
// Who is covered is decided by the including gadget. Define, before the
// include:
//
//   #define ROOT_BARRIER_COVERED(task) my_coverage(task)
//
// an expression on the current task (struct task_struct *) with a value of
// enum root_barrier_coverage:
//
// - ROOT_BARRIER_TASK_NOT_COVERED (0): allow.
// - ROOT_BARRIER_TASK_COVERED (1): deny.
// - ROOT_BARRIER_TASK_FAULT_STRICT: the predicate could not decide (for
//   example a lookup miss while a binding is published), and the class of the
//   task's binding is Strict. Deny, and count the fault.
// - ROOT_BARRIER_TASK_FAULT_AUDIT: the same fault under an Audit class. Allow,
//   and count the fault: Audit never blocks.
//
// Any other value is a fault under Strict. The value must be an integer, not
// a pointer (write `lookup(...) != NULL`). A boolean expression still works:
// it gives 0 or 1. The fault counters (root_barrier_faults) are witness
// counters for the gadget's Ready or degraded status. The predicate should
// read the same published state as the gadget's own verdict (for example the
// same binding route and epoch), so that both agree on a task's class. The
// barrier evaluates the predicate only for an operation that it judges.
//
// A task that the predicate covers, and every task it creates, should stay
// covered. A cgroup-based test does that only when it also matches the
// cgroup's descendants: a task can move itself into a child cgroup it
// creates, and clone3(CLONE_INTO_CGROUP) starts a child in another cgroup. A
// gadget with an exact cgroup scope must keep its tasks in the bound cgroup
// by its own contract (for example, no write access to the cgroup tree).
//
// Optional, before the include:
//
//   #define ROOT_BARRIER_ON_DENY(ctx, op, arg) my_report(ctx, op, arg)
//
// called on each denial, a fault denial included (op is an enum
// root_barrier_op, arg the clone flags, the setns type or the capability), for
// example to send the gadget's own event. Self-test denials do not call it.
//
// Denied operations, and why:
//
// - chroot (path_chroot) and pivot_root (sb_pivotroot): they change the root.
// - A new user namespace (userns_create), from clone, clone3 or unshare. In
//   its own user namespace a task gets every capability, which is what all the
//   other operations below need. Linux 6.1 or later.
// - clone and clone3 with CLONE_NEWNS (task_alloc). The hook reads the clone3
//   flags, which seccomp cannot. Thread creation never sets CLONE_NEWNS, so
//   threads are not affected.
// - unshare(CLONE_NEWNS), and setns into a mount or user namespace (capable,
//   CAP_SYS_ADMIN, with the syscall number and arguments). setns with type 0
//   accepts any namespace type, so it is denied too. setns into another
//   namespace type stays allowed: "docker exec" and "kubectl exec" join the
//   cgroup namespace after the mount namespace, inside the container cgroup,
//   before they exec the command.
// - Changes to the mount tree under the root: mount (sb_mount), move_mount
//   (move_mount), umount (sb_umount), and the CAP_SYS_ADMIN check of
//   open_tree (clone), fsopen, fsconfig, fsmount, fspick and mount_setattr.
//   fsconfig matters for a superblock fd received from another process
//   (reconfigure checks only CAP_SYS_ADMIN). They can put
//   other content at a path under the root, or show content that a mount hid.
//
// Most of these operations also need CAP_SYS_ADMIN or CAP_SYS_CHROOT. The
// capability check runs first, so an unprivileged task without a new user
// namespace already fails with EPERM. The barrier does not depend on that.
//
// A 32-bit (compat) task uses other syscall numbers. The capable program then
// fails closed: it denies every CAP_SYS_ADMIN use of a covered compat task.
//
// The kernel calls a BPF LSM program only while every earlier LSM allowed the
// operation. Each program also returns the denial of an earlier BPF program on
// the same hook unchanged (the trampoline runs the newest program first). The
// previous verdict, `ret`, follows the hook's arguments, so its position
// depends on the hook signature: the Go attestation checks every argument
// count in the kernel's BTF and refuses a kernel where one differs (verified
// equal on 6.8 and 6.12).
//
// User space can cover one more thread through root_barrier_probe, for a
// self-test of the attached programs. It can only add coverage. The thread is
// matched by its id in the PID namespace that user space names and by a nonce
// that the thread sets as its name (comm), so a stale entry does not cover a
// later thread that reuses the id. Each denial of the probe thread sets the
// bit of its operation in the probe entry.
//
// Programs: the header defines one program per hook (rb_<name>). A gadget
// that already has a program on a hook defines ROOT_BARRIER_NO_<NAME>_PROGRAM,
// with the name in upper case (for example ROOT_BARRIER_NO_TASK_ALLOC_PROGRAM
// for rb_task_alloc), and calls the hook body from its own program, first,
// after the check of `ret`:
//
//   ret = root_barrier_task_alloc(ctx, clone_flags);
//   if (ret)
//           return ret;
//
// The barrier then denies before the gadget allocates any state. Separate
// programs on one hook run in link order, which the gadget does not control:
// a gadget that keeps a separate rb_task_alloc must free what it allocated in
// task_free, which the kernel calls when a later task_alloc program denies.
// ROOT_BARRIER_NO_PROGRAMS removes every rb_* program. The Go attestation
// takes the name of the program that carries each hook body.
//
// The barrier keeps no policy state: its maps are the denial and fault
// counters and the probe. A gadget with one long-lived collection keeps the
// barrier links with that collection and never detaches them when it
// publishes a binding or a policy: a publication changes only the state that
// the predicate reads.

#ifndef __ENFORCEMENT_ROOT_BARRIER_H
#define __ENFORCEMENT_ROOT_BARRIER_H

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef ROOT_BARRIER_COVERED
#error "define ROOT_BARRIER_COVERED(task) before including root_barrier.h"
#endif

#ifndef ROOT_BARRIER_ON_DENY
#define ROOT_BARRIER_ON_DENY(ctx, op, arg) \
	do {                               \
	} while (0)
#endif

#define ROOT_BARRIER_EPERM 1
#define ROOT_BARRIER_CAP_SYS_ADMIN 21
#define ROOT_BARRIER_CLONE_NEWNS 0x00020000ULL
#define ROOT_BARRIER_CLONE_NEWUSER 0x10000000ULL

// Operation ids: the counter slots and the op of ROOT_BARRIER_ON_DENY. The
// values are part of the map ABI.
enum root_barrier_op : __u32 {
	ROOT_BARRIER_CHROOT = 0,
	ROOT_BARRIER_PIVOT_ROOT = 1,
	ROOT_BARRIER_USERNS = 2,
	ROOT_BARRIER_CLONE_NS = 3,
	ROOT_BARRIER_UNSHARE_NS = 4,
	ROOT_BARRIER_SETNS = 5,
	ROOT_BARRIER_MOUNT = 6,
	ROOT_BARRIER_MOVE_MOUNT = 7,
	ROOT_BARRIER_UMOUNT = 8,
	ROOT_BARRIER_NEW_MOUNT = 9, // open_tree, fsopen, fsconfig, fsmount, fspick, mount_setattr
	ROOT_BARRIER_COMPAT = 10, // CAP_SYS_ADMIN use of a 32-bit task
	ROOT_BARRIER_OP_MAX = 11,
};

// Denials per operation. User space also finds the instance's programs
// through this map (see the Go attestation).
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, ROOT_BARRIER_OP_MAX);
	__type(key, __u32);
	__type(value, __u64);
} root_barrier_counters SEC(".maps");

// Fault counter slots. The values are part of the map ABI.
enum root_barrier_fault : __u32 {
	ROOT_BARRIER_FAULT_DENIED = 0, // ROOT_BARRIER_TASK_FAULT_STRICT, denied
	ROOT_BARRIER_FAULT_ALLOWED = 1, // ROOT_BARRIER_TASK_FAULT_AUDIT, allowed
	ROOT_BARRIER_FAULT_MAX = 2,
};

// Predicate faults, counted for the operations that the barrier judges.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, ROOT_BARRIER_FAULT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} root_barrier_faults SEC(".maps");

#define ROOT_BARRIER_NONCE_LEN 16

// The thread that user space covers for a self-test.
struct root_barrier_probe {
	// Thread id in the PID namespace of pidns_dev and pidns_ino; 0 = none.
	__u32 tid;
	// Bit (1 << op) of each operation denied to the probe thread.
	__u32 denied;
	__u64 pidns_dev;
	__u64 pidns_ino;
	// The comm of the probe thread, NUL-padded.
	char nonce[ROOT_BARRIER_NONCE_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct root_barrier_probe);
} root_barrier_probe SEC(".maps");

// The value of ROOT_BARRIER_COVERED(task).
enum root_barrier_coverage {
	ROOT_BARRIER_TASK_NOT_COVERED = 0,
	ROOT_BARRIER_TASK_COVERED = 1,
	ROOT_BARRIER_TASK_FAULT_STRICT = 2,
	ROOT_BARRIER_TASK_FAULT_AUDIT = 3,
};

static __always_inline struct root_barrier_probe *root_barrier_probe_entry(void)
{
	__u32 zero = 0;
	struct root_barrier_probe *probe =
		bpf_map_lookup_elem(&root_barrier_probe, &zero);
	struct bpf_pidns_info ns = {};
	__u64 comm[ROOT_BARRIER_NONCE_LEN / 8] = {};
	__u64 nonce[ROOT_BARRIER_NONCE_LEN / 8];

	if (!probe || !probe->tid)
		return NULL;
	if (bpf_get_ns_current_pid_tgid(probe->pidns_dev, probe->pidns_ino, &ns,
					sizeof(ns)) ||
	    ns.pid != probe->tid)
		return NULL;
	if (bpf_get_current_comm(comm, sizeof(comm)))
		return NULL;
	__builtin_memcpy(nonce, probe->nonce, sizeof(nonce));
	return comm[0] == nonce[0] && comm[1] == nonce[1] ? probe : NULL;
}

static __always_inline void root_barrier_count_fault(enum root_barrier_fault f)
{
	__u32 key = f;
	__u64 *count = bpf_map_lookup_elem(&root_barrier_faults, &key);

	if (count)
		(*count)++;
}

// Judges an operation that the barrier denies to a covered task. Returns 0 or
// -EPERM.
static __always_inline int root_barrier_judge(void *ctx,
					      enum root_barrier_op op, __u64 arg)
{
	// A prefixed name: the predicate expands here, in this scope. 64 bits,
	// so that a wide value is a fault and not truncated to "not covered".
	__u64 root_barrier_coverage_value =
		ROOT_BARRIER_COVERED(bpf_get_current_task_btf());
	struct root_barrier_probe *probe = root_barrier_probe_entry();
	__u32 key = op;
	__u64 *count;

	switch (root_barrier_coverage_value) {
	case ROOT_BARRIER_TASK_NOT_COVERED:
		if (!probe)
			return 0;
		break;
	case ROOT_BARRIER_TASK_COVERED:
		break;
	case ROOT_BARRIER_TASK_FAULT_AUDIT:
		root_barrier_count_fault(ROOT_BARRIER_FAULT_ALLOWED);
		if (!probe)
			return 0;
		break;
	default: // ROOT_BARRIER_TASK_FAULT_STRICT, or an unknown value
		root_barrier_count_fault(ROOT_BARRIER_FAULT_DENIED);
		break;
	}
	count = bpf_map_lookup_elem(&root_barrier_counters, &key);
	if (count)
		(*count)++;
	// The probe thread is recorded for the self-test, without an event, also
	// when the predicate covers it.
	if (probe) {
		// Only the probe thread writes this field: no atomic needed.
		probe->denied |= 1U << op;
	} else {
		ROOT_BARRIER_ON_DENY(ctx, op, arg);
	}
	// Keep explicit signed errno branches visible to the verifier.
	volatile int result = -ROOT_BARRIER_EPERM;
	return result;
}

/* Syscall of the current task */

static __always_inline long root_barrier_syscall_nr(void)
{
	struct pt_regs *regs =
		(struct pt_regs *)bpf_task_pt_regs(bpf_get_current_task_btf());

#if defined(__TARGET_ARCH_arm64)
	return BPF_CORE_READ(regs, syscallno);
#elif defined(__TARGET_ARCH_x86)
	return BPF_CORE_READ(regs, orig_ax);
#else
#error "unsupported architecture"
#endif
}

static __always_inline bool root_barrier_compat(void)
{
	struct task_struct *task = bpf_get_current_task_btf();

#if defined(__TARGET_ARCH_arm64)
	struct pt_regs *regs = (struct pt_regs *)bpf_task_pt_regs(task);

	// PSR_MODE32_BIT of the saved user state, as compat_user_mode() checks.
	return BPF_CORE_READ(regs, pstate) & 0x10;
#else
	// TS_COMPAT (ia32), or an x32 syscall (__X32_SYSCALL_BIT in the number).
	return (BPF_CORE_READ(task, thread_info.status) & 0x0002) ||
	       (root_barrier_syscall_nr() & 0x40000000);
#endif
}

static __always_inline __u64 root_barrier_syscall_arg(int n)
{
	struct pt_regs *regs =
		(struct pt_regs *)bpf_task_pt_regs(bpf_get_current_task_btf());

	if (n == 0)
		return PT_REGS_PARM1_CORE_SYSCALL(regs);
	return PT_REGS_PARM2_CORE_SYSCALL(regs);
}

#if defined(__TARGET_ARCH_arm64)
#define ROOT_BARRIER_NR_UNSHARE 97
#define ROOT_BARRIER_NR_SETNS 268
#elif defined(__TARGET_ARCH_x86)
#define ROOT_BARRIER_NR_UNSHARE 272
#define ROOT_BARRIER_NR_SETNS 308
#endif

/* Hook bodies. Each returns 0 or -EPERM. */

static __always_inline int root_barrier_chroot(void *ctx)
{
	return root_barrier_judge(ctx, ROOT_BARRIER_CHROOT, 0);
}

static __always_inline int root_barrier_pivotroot(void *ctx)
{
	return root_barrier_judge(ctx, ROOT_BARRIER_PIVOT_ROOT, 0);
}

static __always_inline int root_barrier_userns(void *ctx)
{
	return root_barrier_judge(ctx, ROOT_BARRIER_USERNS,
				  ROOT_BARRIER_CLONE_NEWUSER);
}

// clone_flags of task_alloc. CLONE_NEWUSER is also judged by userns_create;
// the check here does not depend on that hook.
static __always_inline int root_barrier_task_alloc(void *ctx,
						   unsigned long clone_flags)
{
	__u64 flags = clone_flags &
		      (ROOT_BARRIER_CLONE_NEWNS | ROOT_BARRIER_CLONE_NEWUSER);

	if (!flags)
		return 0;
	return root_barrier_judge(ctx, ROOT_BARRIER_CLONE_NS, flags);
}

static __always_inline int root_barrier_capable(void *ctx, int cap)
{
	long nr;
	__u64 nstype;

	if (cap != ROOT_BARRIER_CAP_SYS_ADMIN)
		return 0;
	if (root_barrier_compat())
		return root_barrier_judge(ctx, ROOT_BARRIER_COMPAT, cap);
	nr = root_barrier_syscall_nr();
	switch (nr) {
	case ROOT_BARRIER_NR_UNSHARE:
		if (root_barrier_syscall_arg(0) & ROOT_BARRIER_CLONE_NEWNS)
			return root_barrier_judge(ctx, ROOT_BARRIER_UNSHARE_NS,
						  ROOT_BARRIER_CLONE_NEWNS);
		return 0;
	case ROOT_BARRIER_NR_SETNS:
		// The kernel checks that a namespace file matches a nonzero
		// type; for a pidfd the type is the set of namespaces joined.
		nstype = (__u32)root_barrier_syscall_arg(1);
		if (!nstype || (nstype & (ROOT_BARRIER_CLONE_NEWNS |
					  ROOT_BARRIER_CLONE_NEWUSER)))
			return root_barrier_judge(ctx, ROOT_BARRIER_SETNS,
						  nstype);
		return 0;
	// Same number on every architecture.
	case 428: // open_tree
	case 430: // fsopen
	case 431: // fsconfig
	case 432: // fsmount
	case 433: // fspick
	case 442: // mount_setattr
	case 467: // open_tree_attr
		return root_barrier_judge(ctx, ROOT_BARRIER_NEW_MOUNT, cap);
	}
	return 0;
}

static __always_inline int root_barrier_mount(void *ctx)
{
	return root_barrier_judge(ctx, ROOT_BARRIER_MOUNT, 0);
}

static __always_inline int root_barrier_move_mount(void *ctx)
{
	return root_barrier_judge(ctx, ROOT_BARRIER_MOVE_MOUNT, 0);
}

static __always_inline int root_barrier_umount(void *ctx)
{
	return root_barrier_judge(ctx, ROOT_BARRIER_UMOUNT, 0);
}

/* Programs */

// ROOT_BARRIER_NO_PROGRAMS, or ROOT_BARRIER_NO_<NAME>_PROGRAM for one hook,
// leaves the hook body to a program of the including gadget (see the top of
// this file).
#ifndef ROOT_BARRIER_NO_PROGRAMS

#ifndef ROOT_BARRIER_NO_CHROOT_PROGRAM
SEC("lsm/path_chroot")
int BPF_PROG(rb_chroot, const struct path *path, int ret)
{
	if (ret)
		return ret;
	return root_barrier_chroot(ctx);
}
#endif

#ifndef ROOT_BARRIER_NO_PIVOTROOT_PROGRAM
SEC("lsm/sb_pivotroot")
int BPF_PROG(rb_pivotroot, const struct path *old_path,
	     const struct path *new_path, int ret)
{
	if (ret)
		return ret;
	return root_barrier_pivotroot(ctx);
}
#endif

#ifndef ROOT_BARRIER_NO_USERNS_PROGRAM
SEC("lsm/userns_create")
int BPF_PROG(rb_userns, const struct cred *cred, int ret)
{
	if (ret)
		return ret;
	return root_barrier_userns(ctx);
}
#endif

#ifndef ROOT_BARRIER_NO_TASK_ALLOC_PROGRAM
SEC("lsm/task_alloc")
int BPF_PROG(rb_task_alloc, struct task_struct *task,
	     unsigned long clone_flags, int ret)
{
	if (ret)
		return ret;
	return root_barrier_task_alloc(ctx, clone_flags);
}
#endif

#ifndef ROOT_BARRIER_NO_CAPABLE_PROGRAM
SEC("lsm/capable")
int BPF_PROG(rb_capable, const struct cred *cred, struct user_namespace *ns,
	     int cap, unsigned int opts, int ret)
{
	if (ret)
		return ret;
	return root_barrier_capable(ctx, cap);
}
#endif

#ifndef ROOT_BARRIER_NO_SB_MOUNT_PROGRAM
SEC("lsm/sb_mount")
int BPF_PROG(rb_sb_mount, const char *dev_name, const struct path *path,
	     const char *type, unsigned long flags, void *data, int ret)
{
	if (ret)
		return ret;
	return root_barrier_mount(ctx);
}
#endif

#ifndef ROOT_BARRIER_NO_MOVE_MOUNT_PROGRAM
SEC("lsm/move_mount")
int BPF_PROG(rb_move_mount, const struct path *from_path,
	     const struct path *to_path, int ret)
{
	if (ret)
		return ret;
	return root_barrier_move_mount(ctx);
}
#endif

#ifndef ROOT_BARRIER_NO_SB_UMOUNT_PROGRAM
SEC("lsm/sb_umount")
int BPF_PROG(rb_sb_umount, struct vfsmount *mnt, int flags, int ret)
{
	if (ret)
		return ret;
	return root_barrier_umount(ctx);
}
#endif

#endif /* ROOT_BARRIER_NO_PROGRAMS */

#endif /* __ENFORCEMENT_ROOT_BARRIER_H */
