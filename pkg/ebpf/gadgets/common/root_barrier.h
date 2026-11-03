// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Kubescape Authors

// Root barrier: BPF LSM programs that stop a covered task from changing its
// root or its mount namespace, and from changing the mount tree under its root.
// An enforcer that checks a task's root from time to time (for example at each
// exec) needs this, because the task could otherwise change its root between
// two checks.
//
// The barrier always denies. It has no mode and no policy map: it is an
// invariant of the including gadget, not a rule.
//
// Who is covered is decided by the including gadget. Define, before the
// include:
//
//   #define ROOT_BARRIER_COVERED(task) my_covered(task)
//
// a boolean expression on the current task (struct task_struct *). A task that
// the expression covers, and every task it creates, must stay covered: a
// cgroup-based test does that, because a child starts in its parent's cgroup.
//
// Optional, before the include:
//
//   #define ROOT_BARRIER_ON_DENY(ctx, op, arg) my_report(ctx, op, arg)
//
// called on each denial (op is an enum root_barrier_op, arg the clone flags,
// the setns type or the capability), for example to send the gadget's own event.
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
//   open_tree (clone), fsopen, fsmount, fspick and mount_setattr. They can put
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
// the same hook unchanged.
//
// User space can cover one more thread through root_barrier_probe, for a
// self-test of the attached programs. It can only add coverage.

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
	ROOT_BARRIER_NEW_MOUNT = 9, // open_tree, fsopen, fsmount, fspick, mount_setattr
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

// Thread id (not process id) that user space covers for a self-test; 0 = none.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} root_barrier_probe SEC(".maps");

static __always_inline bool root_barrier_covered(void)
{
	struct task_struct *task = bpf_get_current_task_btf();
	__u32 zero = 0;
	__u32 *probe;

	if (ROOT_BARRIER_COVERED(task))
		return true;
	probe = bpf_map_lookup_elem(&root_barrier_probe, &zero);
	return probe && *probe && *probe == (__u32)bpf_get_current_pid_tgid();
}

static __always_inline int root_barrier_deny(void *ctx, enum root_barrier_op op,
					     __u64 arg)
{
	__u32 key = op;
	__u64 *count = bpf_map_lookup_elem(&root_barrier_counters, &key);

	if (count)
		(*count)++;
	ROOT_BARRIER_ON_DENY(ctx, op, arg);
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
	return BPF_CORE_READ(task, thread_info.flags) & (1UL << 22); // TIF_32BIT
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
	if (!root_barrier_covered())
		return 0;
	return root_barrier_deny(ctx, ROOT_BARRIER_CHROOT, 0);
}

static __always_inline int root_barrier_pivotroot(void *ctx)
{
	if (!root_barrier_covered())
		return 0;
	return root_barrier_deny(ctx, ROOT_BARRIER_PIVOT_ROOT, 0);
}

static __always_inline int root_barrier_userns(void *ctx)
{
	if (!root_barrier_covered())
		return 0;
	return root_barrier_deny(ctx, ROOT_BARRIER_USERNS,
				 ROOT_BARRIER_CLONE_NEWUSER);
}

// clone_flags of task_alloc. CLONE_NEWUSER is also judged by userns_create;
// the check here does not depend on that hook.
static __always_inline int root_barrier_task_alloc(void *ctx,
						   unsigned long clone_flags)
{
	__u64 flags = clone_flags &
		      (ROOT_BARRIER_CLONE_NEWNS | ROOT_BARRIER_CLONE_NEWUSER);

	if (!flags || !root_barrier_covered())
		return 0;
	return root_barrier_deny(ctx, ROOT_BARRIER_CLONE_NS, flags);
}

static __always_inline int root_barrier_capable(void *ctx, int cap)
{
	long nr;
	__u64 nstype;

	if (cap != ROOT_BARRIER_CAP_SYS_ADMIN || !root_barrier_covered())
		return 0;
	if (root_barrier_compat())
		return root_barrier_deny(ctx, ROOT_BARRIER_COMPAT, cap);
	nr = root_barrier_syscall_nr();
	switch (nr) {
	case ROOT_BARRIER_NR_UNSHARE:
		if (root_barrier_syscall_arg(0) & ROOT_BARRIER_CLONE_NEWNS)
			return root_barrier_deny(ctx, ROOT_BARRIER_UNSHARE_NS,
						 ROOT_BARRIER_CLONE_NEWNS);
		return 0;
	case ROOT_BARRIER_NR_SETNS:
		// The kernel checks that a namespace file matches a nonzero
		// type; for a pidfd the type is the set of namespaces joined.
		nstype = (__u32)root_barrier_syscall_arg(1);
		if (!nstype || (nstype & (ROOT_BARRIER_CLONE_NEWNS |
					  ROOT_BARRIER_CLONE_NEWUSER)))
			return root_barrier_deny(ctx, ROOT_BARRIER_SETNS,
						 nstype);
		return 0;
	// Same number on every architecture.
	case 428: // open_tree
	case 430: // fsopen
	case 432: // fsmount
	case 433: // fspick
	case 442: // mount_setattr
	case 467: // open_tree_attr
		return root_barrier_deny(ctx, ROOT_BARRIER_NEW_MOUNT, cap);
	}
	return 0;
}

static __always_inline int root_barrier_mount(void *ctx)
{
	if (!root_barrier_covered())
		return 0;
	return root_barrier_deny(ctx, ROOT_BARRIER_MOUNT, 0);
}

static __always_inline int root_barrier_move_mount(void *ctx)
{
	if (!root_barrier_covered())
		return 0;
	return root_barrier_deny(ctx, ROOT_BARRIER_MOVE_MOUNT, 0);
}

static __always_inline int root_barrier_umount(void *ctx)
{
	if (!root_barrier_covered())
		return 0;
	return root_barrier_deny(ctx, ROOT_BARRIER_UMOUNT, 0);
}

/* Programs */

// A gadget that attaches the bodies from its own programs defines
// ROOT_BARRIER_NO_PROGRAMS. The Go attestation expects these program names.
#ifndef ROOT_BARRIER_NO_PROGRAMS

SEC("lsm/path_chroot")
int BPF_PROG(rb_chroot, const struct path *path, int ret)
{
	if (ret)
		return ret;
	return root_barrier_chroot(ctx);
}

SEC("lsm/sb_pivotroot")
int BPF_PROG(rb_pivotroot, const struct path *old_path,
	     const struct path *new_path, int ret)
{
	if (ret)
		return ret;
	return root_barrier_pivotroot(ctx);
}

SEC("lsm/userns_create")
int BPF_PROG(rb_userns, const struct cred *cred, int ret)
{
	if (ret)
		return ret;
	return root_barrier_userns(ctx);
}

SEC("lsm/task_alloc")
int BPF_PROG(rb_task_alloc, struct task_struct *task,
	     unsigned long clone_flags, int ret)
{
	if (ret)
		return ret;
	return root_barrier_task_alloc(ctx, clone_flags);
}

SEC("lsm/capable")
int BPF_PROG(rb_capable, const struct cred *cred, struct user_namespace *ns,
	     int cap, unsigned int opts, int ret)
{
	if (ret)
		return ret;
	return root_barrier_capable(ctx, cap);
}

SEC("lsm/sb_mount")
int BPF_PROG(rb_sb_mount, const char *dev_name, const struct path *path,
	     const char *type, unsigned long flags, void *data, int ret)
{
	if (ret)
		return ret;
	return root_barrier_mount(ctx);
}

SEC("lsm/move_mount")
int BPF_PROG(rb_move_mount, const struct path *from_path,
	     const struct path *to_path, int ret)
{
	if (ret)
		return ret;
	return root_barrier_move_mount(ctx);
}

SEC("lsm/sb_umount")
int BPF_PROG(rb_sb_umount, struct vfsmount *mnt, int flags, int ret)
{
	if (ret)
		return ret;
	return root_barrier_umount(ctx);
}

#endif /* ROOT_BARRIER_NO_PROGRAMS */

#endif /* __ENFORCEMENT_ROOT_BARRIER_H */
