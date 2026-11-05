// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Kubescape Authors

// enforce_privilege: enforce a privilege policy (namespaces, mounts,
// capabilities, ptrace, modules and more) for a set of containers with BPF
// LSM. The program is fixed; the policy is map data (privilege_policy.h),
// frozen per instance; a rule change starts a replacement instance. Audit and
// enforce share one code path: the rank of the deciding entry carries the mode.
//
// Notes that apply to every hook:
// - Only armed tasks are judged (see arming.h).
// - A deny returns -EPERM from the LSM hook, before the side effect.
// - The kernel calls the next BPF LSM program only while every earlier one
//   returned 0 (the trampoline runs the newest program first and stops at the
//   first nonzero return; runtime_kernel_test.go, TestEarlierBPFDenyHolds).
//   Each hook also returns an earlier BPF verdict, `ret`, unchanged, as the
//   other enforcement gadgets do. `ret` follows the hook arguments, so its
//   position depends on the hook signature: the operator checks every
//   argument count in the kernel's BTF (runtime.Hooks) and refuses a kernel
//   where one differs.
// - Each hook body is a plain function, so it can also be attached as
//   fmod_ret on the matching security_* function.

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/macros.h>

#include "../common/arming.h"
#include "../common/verdict.h"
#include "privilege_policy.h"

char LICENSE[] SEC("license") = "GPL";

GADGET_PARAM(host_mntns_id);
GADGET_PARAM(arming_fail_fork_marks);

#define EPERM 1
#define ENOMEM 12
#define CAP_SYS_ADMIN 21
#define CAP_OPT_NOAUDIT (1UL << 1)
#define PTRACE_MODE_ATTACH 0x02

#define CLONE_NEWTIME 0x00000080ULL
#define CLONE_INTO_CGROUP 0x200000000ULL
#define CLONE_NEWNS 0x00020000ULL
#define CLONE_NEWCGROUP 0x02000000ULL
#define CLONE_NEWUTS 0x04000000ULL
#define CLONE_NEWIPC 0x08000000ULL
#define CLONE_NEWUSER 0x10000000ULL
#define CLONE_NEWPID 0x20000000ULL
#define CLONE_NEWNET 0x40000000ULL
#define CLONE_NS_MASK                                                   \
	(CLONE_NEWTIME | CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | \
	 CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET)

// Architecture-independent syscall ids. The values are part of the map ABI.
enum priv_syscall : __u32 {
	PRIV_SC_NONE = 0,
	PRIV_SC_UNSHARE = 1,
	PRIV_SC_SETNS = 2,
	PRIV_SC_CLONE = 3,
	PRIV_SC_CLONE3 = 4,
	PRIV_SC_MOUNT = 5,
	PRIV_SC_UMOUNT2 = 6,
	PRIV_SC_PIVOT_ROOT = 7,
	PRIV_SC_CHROOT = 8,
	PRIV_SC_OPEN_TREE = 9,
	PRIV_SC_MOVE_MOUNT = 10,
	PRIV_SC_FSOPEN = 11,
	PRIV_SC_FSMOUNT = 12,
	PRIV_SC_FSPICK = 13,
	PRIV_SC_MOUNT_SETATTR = 14,
	PRIV_SC_PTRACE = 15,
	PRIV_SC_PROCESS_VM_READV = 16,
	PRIV_SC_PROCESS_VM_WRITEV = 17,
	PRIV_SC_INIT_MODULE = 18,
	PRIV_SC_FINIT_MODULE = 19,
	PRIV_SC_BPF = 20,
	PRIV_SC_PERF_EVENT_OPEN = 21,
	PRIV_SC_KEXEC_LOAD = 22,
	PRIV_SC_KEYCTL = 23,
	PRIV_SC_USERFAULTFD = 24,
	PRIV_SC_IO_URING_SETUP = 25,
	PRIV_SC_MKNOD = 26,
	PRIV_SC_SETUID = 27,
	PRIV_SC_SETGID = 28,
	PRIV_SC_CAPSET = 29,
};

enum priv_hook : __u32 {
	PRIV_HOOK_USERNS_CREATE,
	PRIV_HOOK_TASK_ALLOC,
	PRIV_HOOK_CAPABLE,
	PRIV_HOOK_SB_MOUNT,
	PRIV_HOOK_SB_KERN_MOUNT,
	PRIV_HOOK_SB_UMOUNT,
	PRIV_HOOK_MOVE_MOUNT,
	PRIV_HOOK_SB_PIVOTROOT,
	PRIV_HOOK_PATH_CHROOT,
	PRIV_HOOK_ANON_INODE,
	PRIV_HOOK_PTRACE_ACCESS_CHECK,
	PRIV_HOOK_PTRACE_TRACEME,
	PRIV_HOOK_KERNEL_READ_FILE,
	PRIV_HOOK_KERNEL_LOAD_DATA,
	PRIV_HOOK_KERNEL_MODULE_REQUEST,
	PRIV_HOOK_BPF,
	PRIV_HOOK_PERF_EVENT_OPEN,
	PRIV_HOOK_KEY_ALLOC,
	PRIV_HOOK_KEY_PERMISSION,
	PRIV_HOOK_INODE_MKNOD,
	PRIV_HOOK_TASK_FIX_SETUID,
	PRIV_HOOK_TASK_FIX_SETGID,
	PRIV_HOOK_CAPSET,
};

struct event {
	VERDICT_BASE_FIELDS;
	__u32 host_pid;
	// Rule and origin ids of the deciding rule or default.
	__u32 rule_id;
	__u32 origin_id;
	// 1 when a section default decided, not a rule.
	__u32 is_default;
	char comm[16];
	enum priv_hook hook_raw;
	enum priv_syscall syscall_raw;
	// CLONE_NEW* flags of a namespace call.
	__u64 flags;
	// Capability number; -1 when the hook is not a capability check.
	__s32 capability;
	char fstype[PRIV_NAME_LEN];
	// Policy slot (combination of policies) of the bound container.
	__u32 slot;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} events SEC(".maps");
GADGET_TRACER(verdict, events, event);

// What a hook tried to do. Used for the event only.
struct priv_target {
	enum priv_syscall sc;
	__u64 flags;
	__s32 cap;
	char fstype[PRIV_NAME_LEN];
};

/* Syscall numbers */

static __always_inline long current_syscall_nr(void)
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

// A 32-bit (compat) task uses other syscall numbers. Hooks that decide by
// syscall number fail closed for it: they apply every candidate syscall.
static __always_inline bool current_is_compat(void)
{
	struct task_struct *task = bpf_get_current_task_btf();

#if defined(__TARGET_ARCH_arm64)
	return BPF_CORE_READ(task, thread_info.flags) & (1UL << 22); // TIF_32BIT
#else
	// TS_COMPAT (ia32), or an x32 syscall (__X32_SYSCALL_BIT in the number).
	return (BPF_CORE_READ(task, thread_info.status) & 0x0002) ||
	       (current_syscall_nr() & 0x40000000);
#endif
}

static __always_inline __u64 current_syscall_arg(int n)
{
	struct pt_regs *regs =
		(struct pt_regs *)bpf_task_pt_regs(bpf_get_current_task_btf());

	if (n == 0)
		return PT_REGS_PARM1_CORE_SYSCALL(regs);
	return PT_REGS_PARM2_CORE_SYSCALL(regs);
}

// Native syscall number -> priv_syscall. Compat (32-bit) numbers are not
// mapped.
static __always_inline enum priv_syscall priv_syscall_from_nr(long nr)
{
	if (current_is_compat())
		return PRIV_SC_NONE;
	switch (nr) {
	// Same number on every architecture.
	case 425:
		return PRIV_SC_IO_URING_SETUP;
	case 428:
		return PRIV_SC_OPEN_TREE;
	case 429:
		return PRIV_SC_MOVE_MOUNT;
	case 430:
		return PRIV_SC_FSOPEN;
	case 432:
		return PRIV_SC_FSMOUNT;
	case 433:
		return PRIV_SC_FSPICK;
	case 435:
		return PRIV_SC_CLONE3;
	case 442:
		return PRIV_SC_MOUNT_SETATTR;
	case 467: // open_tree_attr
		return PRIV_SC_OPEN_TREE;
#if defined(__TARGET_ARCH_arm64)
	case 97:
		return PRIV_SC_UNSHARE;
	case 268:
		return PRIV_SC_SETNS;
	case 220:
		return PRIV_SC_CLONE;
	case 40:
		return PRIV_SC_MOUNT;
	case 39:
		return PRIV_SC_UMOUNT2;
	case 41:
		return PRIV_SC_PIVOT_ROOT;
	case 51:
		return PRIV_SC_CHROOT;
	case 117:
		return PRIV_SC_PTRACE;
	case 270:
		return PRIV_SC_PROCESS_VM_READV;
	case 271:
		return PRIV_SC_PROCESS_VM_WRITEV;
	case 105:
		return PRIV_SC_INIT_MODULE;
	case 273:
		return PRIV_SC_FINIT_MODULE;
	case 104:
	case 294:
		return PRIV_SC_KEXEC_LOAD;
	case 33: // mknodat; arm64 has no mknod
		return PRIV_SC_MKNOD;
#elif defined(__TARGET_ARCH_x86)
	case 272:
		return PRIV_SC_UNSHARE;
	case 308:
		return PRIV_SC_SETNS;
	case 56:
		return PRIV_SC_CLONE;
	case 165:
		return PRIV_SC_MOUNT;
	case 166:
		return PRIV_SC_UMOUNT2;
	case 155:
		return PRIV_SC_PIVOT_ROOT;
	case 161:
		return PRIV_SC_CHROOT;
	case 101:
		return PRIV_SC_PTRACE;
	case 310:
		return PRIV_SC_PROCESS_VM_READV;
	case 311:
		return PRIV_SC_PROCESS_VM_WRITEV;
	case 175:
		return PRIV_SC_INIT_MODULE;
	case 313:
		return PRIV_SC_FINIT_MODULE;
	case 246:
	case 320:
		return PRIV_SC_KEXEC_LOAD;
	case 133:
	case 259:
		return PRIV_SC_MKNOD;
#endif
	}
	return PRIV_SC_NONE;
}

/* Resolution */

static __always_inline void consider_syscall(__u32 slot, enum priv_syscall sc,
					     __u64 qual,
					     struct policy_match *m)
{
	struct priv_key key = { .slot = slot };

	key.kind = PRIV_KIND_SYSCALL;
	key.id = sc;
	key.qual = qual;
	priv_consider(&key, m);
}

struct resolve_flags_ctx {
	__u32 slot;
	enum priv_syscall sc;
	__u64 flags;
	struct policy_match base;
	struct policy_match out;
};

static __always_inline __u64 ns_flag_at(__u32 i)
{
	switch (i) {
	case 0:
		return CLONE_NEWNS;
	case 1:
		return CLONE_NEWCGROUP;
	case 2:
		return CLONE_NEWUTS;
	case 3:
		return CLONE_NEWIPC;
	case 4:
		return CLONE_NEWUSER;
	case 5:
		return CLONE_NEWPID;
	case 6:
		return CLONE_NEWNET;
	case 7:
		return CLONE_NEWTIME;
	}
	return 0;
}

// resolve_flag is a bpf_loop callback: one namespace flag of the call.
static long resolve_flag(__u32 i, void *data)
{
	struct resolve_flags_ctx *c = data;
	__u64 flag = ns_flag_at(i);
	struct policy_match m;

	if (!flag)
		return 1;
	if (!(c->flags & flag))
		return 0;
	m = c->base;
	consider_syscall(c->slot, c->sc, flag, &m);
	priv_finish_kind(c->slot, PRIV_KIND_SYSCALL, &m);
	policy_merge(&c->out, &m);
	return 0;
}

// resolve_syscall resolves the syscall kind. Each namespace flag of a call
// resolves on its own (rules on the flag or on the syscall with any flag, else
// the default), so an allow for one flag never lets another flag of the same
// call pass. The per-flag work runs in bpf_loop to keep verification small.
static __always_inline void resolve_syscall(__u32 slot, enum priv_syscall sc,
					    __u64 flags, struct policy_match *out)
{
	struct resolve_flags_ctx c = { .slot = slot, .sc = sc, .flags = flags };

	consider_syscall(slot, sc, 0, &c.base);
	if (!(flags & CLONE_NS_MASK)) {
		priv_finish_kind(slot, PRIV_KIND_SYSCALL, &c.base);
		policy_merge(out, &c.base);
		return;
	}
	bpf_loop(8, resolve_flag, &c, 0);
	policy_merge(out, &c.out);
}

static __always_inline void resolve_capability(__u32 slot, int cap,
					       struct policy_match *out)
{
	struct priv_key key = { .slot = slot };
	struct policy_match m = {};

	key.kind = PRIV_KIND_CAPABILITY;
	key.id = cap;
	priv_consider(&key, &m);
	priv_finish_kind(slot, PRIV_KIND_CAPABILITY, &m);
	policy_merge(out, &m);
}

static __always_inline void resolve_fstype(__u32 slot, const char *fstype,
					   struct policy_match *out)
{
	struct priv_key key = { .slot = slot };
	struct policy_match m = {};

	key.kind = PRIV_KIND_MOUNT_FSTYPE;
	__builtin_memcpy(key.name, fstype, PRIV_NAME_LEN);
	priv_consider(&key, &m);
	priv_finish_kind(slot, PRIV_KIND_MOUNT_FSTYPE, &m);
	policy_merge(out, &m);
}

/* Scope and verdict */

// priv_scope returns the policy header for an armed task in a bound cgroup,
// or NULL.
static __always_inline struct policy_value *priv_scope(__u64 *cgid, __u32 *slot)
{
	if (!arming_task_armed(bpf_get_current_task_btf()))
		return NULL;
	return priv_header(cgid, slot);
}

static __always_inline int priv_verdict(void *ctx, enum priv_hook hook,
					const struct priv_target *t,
					const struct policy_value *header,
					__u64 cgid, __u32 slot,
					const struct policy_match *m)
{
	struct event *e;
	bool reporting;

	if (m->rank < POLICY_RANK_DENY_AUDIT) {
		if (m->rank == POLICY_RANK_ALLOW)
			verdict_count(VERDICT_COUNT_ALLOWED);
		return 0;
	}
	verdict_count(VERDICT_COUNT_DENIED);

	reporting = verdict_report_allowed();
	e = reporting ? bpf_ringbuf_reserve(&events, sizeof(*e), 0) : NULL;
	if (e) {
		VERDICT_FILL_BASE(e, m, header->generation, cgid);
		e->host_pid = bpf_get_current_pid_tgid() >> 32;
		e->rule_id = m->rule_id;
		e->origin_id = m->origin_id;
		e->is_default = m->is_default;
		e->slot = slot;
		bpf_get_current_comm(e->comm, sizeof(e->comm));
		e->hook_raw = hook;
		e->syscall_raw = t->sc;
		e->flags = t->flags;
		e->capability = t->cap;
		__builtin_memcpy(e->fstype, t->fstype, PRIV_NAME_LEN);
		bpf_ringbuf_submit(e, 0);
		verdict_count(VERDICT_COUNT_SUBMITTED);
	} else {
		verdict_count(reporting ? VERDICT_COUNT_DROPPED :
					  VERDICT_COUNT_RATE_LIMITED);
	}

	// Keep explicit signed errno branches visible to the verifier.
	volatile int result = 0;
	if (m->rank == POLICY_RANK_DENY_ENFORCE)
		result = -EPERM;
	return result;
}

// check_syscall is the common body of hooks that map to one syscall.
static __always_inline int check_syscall(void *ctx, enum priv_hook hook,
					 enum priv_syscall sc, __u64 flags)
{
	struct priv_target t = { .sc = sc, .flags = flags, .cap = -1 };
	struct policy_match m = {};
	__u64 cgid = 0;
	__u32 slot = 0;
	struct policy_value *header;

	if (sc == PRIV_SC_NONE)
		return 0;
	header = priv_scope(&cgid, &slot);
	if (!header)
		return 0;
	resolve_syscall(slot, sc, flags, &m);
	return priv_verdict(ctx, hook, &t, header, cgid, slot, &m);
}

/* Arming */

// priv_enforcing_slot returns true, with the slot, when the current task is
// in a bound cgroup whose slot enforces.
static __always_inline bool priv_enforcing_slot(__u32 *slot)
{
	struct policy_value *header;
	__u64 cgid = 0;

	header = priv_header(&cgid, slot);
	return header && header->mode == POLICY_MODE_ENFORCE;
}

// The exec hook cannot fail the exec. A lost mark in an enforcing slot is a
// tracking fault: the owner reports the binding as not confirmed.
SEC("lsm/bprm_committed_creds")
int BPF_PROG(ig_priv_exec)
{
	__u32 slot = 0;

	if (!arming_on_exec()) {
		verdict_count(VERDICT_COUNT_SECTION_ERROR);
		if (priv_enforcing_slot(&slot))
			arming_slot_fault(slot);
	}
	return 0;
}

// priv_lost_child handles an armed parent whose child could not be marked.
// An unmarked child would escape every rule, so an enforcing slot refuses the
// fork and counts a tracking fault. An audit slot or an unbound cgroup allows
// it; the failure is in the section error counter only. A clone into another
// cgroup is refused too, because the child's binding is not known here.
static __always_inline int priv_lost_child(unsigned long clone_flags)
{
	__u32 slot = 0;

	verdict_count(VERDICT_COUNT_SECTION_ERROR);
	if (priv_enforcing_slot(&slot)) {
		arming_slot_fault(slot);
		return -ENOMEM;
	}
	if ((__u64)clone_flags & CLONE_INTO_CGROUP)
		return -ENOMEM;
	return 0;
}

/* Namespaces */

static __always_inline int do_userns_create(void *ctx)
{
	enum priv_syscall sc = priv_syscall_from_nr(current_syscall_nr());
	struct priv_target t = { .flags = CLONE_NEWUSER, .cap = -1 };
	struct policy_match m = {};
	__u64 cgid = 0;
	__u32 slot = 0;
	struct policy_value *header;

	header = priv_scope(&cgid, &slot);
	if (!header)
		return 0;

	if (sc == PRIV_SC_UNSHARE || sc == PRIV_SC_CLONE ||
	    sc == PRIV_SC_CLONE3) {
		t.sc = sc;
		resolve_syscall(slot, sc, CLONE_NEWUSER, &m);
	} else {
		// Unknown entry point (for example a compat syscall): apply the
		// most limiting rule of the three namespace-creating syscalls.
		t.sc = PRIV_SC_UNSHARE;
		resolve_syscall(slot, PRIV_SC_UNSHARE, CLONE_NEWUSER, &m);
		resolve_syscall(slot, PRIV_SC_CLONE, CLONE_NEWUSER, &m);
		resolve_syscall(slot, PRIV_SC_CLONE3, CLONE_NEWUSER, &m);
	}
	return priv_verdict(ctx, PRIV_HOOK_USERNS_CREATE, &t, header, cgid, slot, &m);
}

SEC("lsm/userns_create")
int BPF_PROG(ig_priv_userns, const struct cred *cred, int ret)
{
	if (ret)
		return ret;
	return do_userns_create(ctx);
}

static __always_inline int do_task_alloc(void *ctx, struct task_struct *task,
					 unsigned long clone_flags)
{
	enum priv_syscall sc;
	__u64 flags;

	if (!arming_on_fork(task, clone_flags) && priv_lost_child(clone_flags))
		return -ENOMEM;

	// userns_create judges CLONE_NEWUSER.
	flags = clone_flags & CLONE_NS_MASK & ~CLONE_NEWUSER;
	if (current_is_compat() && flags) {
		// Unknown syscall: apply clone and clone3 rules, all flags.
		struct priv_target t = { .sc = PRIV_SC_CLONE3, .flags = flags, .cap = -1 };
		struct policy_match m = {};
		struct policy_value *header;
		__u64 cgid = 0;
		__u32 slot = 0;

		header = priv_scope(&cgid, &slot);
		if (!header)
			return 0;
		resolve_syscall(slot, PRIV_SC_CLONE, flags, &m);
		resolve_syscall(slot, PRIV_SC_CLONE3, flags, &m);
		return priv_verdict(ctx, PRIV_HOOK_TASK_ALLOC, &t, header, cgid, slot, &m);
	}
	sc = priv_syscall_from_nr(current_syscall_nr()) == PRIV_SC_CLONE3 ?
		     PRIV_SC_CLONE3 :
		     PRIV_SC_CLONE;
	// In clone(2) the CLONE_NEWTIME bit is part of the exit signal.
	if (sc == PRIV_SC_CLONE)
		flags &= ~CLONE_NEWTIME;
	if (!flags)
		return 0;
	return check_syscall(ctx, PRIV_HOOK_TASK_ALLOC, sc, flags);
}

SEC("lsm/task_alloc")
int BPF_PROG(ig_priv_task_alloc, struct task_struct *task, unsigned long clone_flags, int ret)
{
	if (ret)
		return ret;
	return do_task_alloc(ctx, task, clone_flags);
}

/* Capabilities */

// Syscalls whose only LSM hook is the CAP_SYS_ADMIN check, and the CLONE_NEW*
// flags they act on.
static __always_inline enum priv_syscall capable_syscall(__u64 *flags)
{
	enum priv_syscall sc = priv_syscall_from_nr(current_syscall_nr());

	*flags = 0;
	switch (sc) {
	case PRIV_SC_UNSHARE:
		*flags = current_syscall_arg(0) & CLONE_NS_MASK & ~CLONE_NEWUSER;
		return sc;
	case PRIV_SC_SETNS:
		*flags = current_syscall_arg(1) & CLONE_NS_MASK;
		// nstype 0 accepts any namespace type: apply every flag rule.
		if (!*flags)
			*flags = CLONE_NS_MASK;
		return sc;
	case PRIV_SC_OPEN_TREE:
	case PRIV_SC_FSOPEN:
	case PRIV_SC_FSMOUNT:
	case PRIV_SC_FSPICK:
	case PRIV_SC_MOUNT_SETATTR:
		return sc;
	default:
		// mount, umount2, pivot_root, chroot and move_mount have their
		// own hooks.
		return PRIV_SC_NONE;
	}
}

static __always_inline int do_capable(void *ctx, const struct cred *cred,
				      int cap, unsigned int opts)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct priv_target t = { .cap = cap };
	struct policy_match m = {};
	__u64 cgid = 0;
	__u32 slot = 0;
	struct policy_value *header;

	// Kernel probes that do not grant an action (for example the overcommit
	// check).
	if (opts & CAP_OPT_NOAUDIT)
		return 0;
	// Overridden credentials, for example overlayfs copy-up with the
	// mounter's credentials. Denying those breaks writes to the container
	// root filesystem.
	if ((void *)cred != (void *)task->real_cred)
		return 0;
	header = priv_scope(&cgid, &slot);
	if (!header)
		return 0;

	resolve_capability(slot, cap, &m);
	if (cap == CAP_SYS_ADMIN && current_is_compat()) {
		// Unknown syscall: apply every syscall judged at this check.
		t.flags = CLONE_NS_MASK & ~CLONE_NEWUSER;
		resolve_syscall(slot, PRIV_SC_UNSHARE, t.flags, &m);
		resolve_syscall(slot, PRIV_SC_SETNS, CLONE_NS_MASK, &m);
		resolve_syscall(slot, PRIV_SC_OPEN_TREE, 0, &m);
		resolve_syscall(slot, PRIV_SC_FSOPEN, 0, &m);
		resolve_syscall(slot, PRIV_SC_FSMOUNT, 0, &m);
		resolve_syscall(slot, PRIV_SC_FSPICK, 0, &m);
		resolve_syscall(slot, PRIV_SC_MOUNT_SETATTR, 0, &m);
	} else if (cap == CAP_SYS_ADMIN) {
		t.sc = capable_syscall(&t.flags);
		if (t.sc != PRIV_SC_NONE)
			resolve_syscall(slot, t.sc, t.flags, &m);
	}
	return priv_verdict(ctx, PRIV_HOOK_CAPABLE, &t, header, cgid, slot, &m);
}

SEC("lsm/capable")
int BPF_PROG(ig_priv_capable, const struct cred *cred, struct user_namespace *ns, int cap, unsigned int opts, int ret)
{
	if (ret)
		return ret;
	return do_capable(ctx, cred, cap, opts);
}

SEC("lsm/capset")
int BPF_PROG(ig_priv_capset, struct cred *new, const struct cred *old, const kernel_cap_t *effective, const kernel_cap_t *inheritable, const kernel_cap_t *permitted, int ret)
{
	if (ret)
		return ret;
	return check_syscall(ctx, PRIV_HOOK_CAPSET, PRIV_SC_CAPSET, 0);
}

SEC("lsm/task_fix_setuid")
int BPF_PROG(ig_priv_setuid, struct cred *new, const struct cred *old, int flags, int ret)
{
	if (ret)
		return ret;
	return check_syscall(ctx, PRIV_HOOK_TASK_FIX_SETUID, PRIV_SC_SETUID, 0);
}

SEC("lsm/task_fix_setgid")
int BPF_PROG(ig_priv_setgid, struct cred *new, const struct cred *old, int flags, int ret)
{
	if (ret)
		return ret;
	return check_syscall(ctx, PRIV_HOOK_TASK_FIX_SETGID, PRIV_SC_SETGID, 0);
}

/* Mounts */

SEC("lsm/sb_mount")
int BPF_PROG(ig_priv_sb_mount, const char *dev_name, const struct path *path, const char *type, unsigned long flags, void *data, int ret)
{
	if (ret)
		return ret;
	return check_syscall(ctx, PRIV_HOOK_SB_MOUNT, PRIV_SC_MOUNT, 0);
}

// A new superblock, from mount(2) or from fsconfig(FSCONFIG_CMD_CREATE).
// Judging here also covers detached mounts (fsmount without move_mount).
static __always_inline int do_sb_kern_mount(void *ctx,
					    const struct super_block *sb)
{
	struct priv_target t = { .cap = -1 };
	struct policy_match m = {};
	__u64 cgid = 0;
	__u32 slot = 0;
	struct policy_value *header;

	header = priv_scope(&cgid, &slot);
	if (!header)
		return 0;
	bpf_probe_read_kernel_str(t.fstype, sizeof(t.fstype),
				  BPF_CORE_READ(sb, s_type, name));
	t.sc = priv_syscall_from_nr(current_syscall_nr());
	resolve_fstype(slot, t.fstype, &m);
	return priv_verdict(ctx, PRIV_HOOK_SB_KERN_MOUNT, &t, header, cgid, slot, &m);
}

SEC("lsm/sb_kern_mount")
int BPF_PROG(ig_priv_sb_kern_mount, const struct super_block *sb, int ret)
{
	if (ret)
		return ret;
	return do_sb_kern_mount(ctx, sb);
}

SEC("lsm/sb_umount")
int BPF_PROG(ig_priv_sb_umount, struct vfsmount *mnt, int flags, int ret)
{
	if (ret)
		return ret;
	return check_syscall(ctx, PRIV_HOOK_SB_UMOUNT, PRIV_SC_UMOUNT2, 0);
}

SEC("lsm/move_mount")
int BPF_PROG(ig_priv_move_mount, const struct path *from_path, const struct path *to_path, int ret)
{
	if (ret)
		return ret;
	return check_syscall(ctx, PRIV_HOOK_MOVE_MOUNT, PRIV_SC_MOVE_MOUNT, 0);
}

SEC("lsm/sb_pivotroot")
int BPF_PROG(ig_priv_pivotroot, const struct path *old_path, const struct path *new_path, int ret)
{
	if (ret)
		return ret;
	return check_syscall(ctx, PRIV_HOOK_SB_PIVOTROOT, PRIV_SC_PIVOT_ROOT,
			     0);
}

SEC("lsm/path_chroot")
int BPF_PROG(ig_priv_chroot, const struct path *path, int ret)
{
	if (ret)
		return ret;
	return check_syscall(ctx, PRIV_HOOK_PATH_CHROOT, PRIV_SC_CHROOT, 0);
}

/* io_uring and userfaultfd */

static __always_inline int do_anon_inode(void *ctx, const struct qstr *name)
{
	char buf[16] = {};

	bpf_probe_read_kernel_str(buf, sizeof(buf), BPF_CORE_READ(name, name));
	// "[io_uring]"
	if (buf[0] == '[' && buf[1] == 'i' && buf[2] == 'o' && buf[3] == '_' &&
	    buf[4] == 'u' && buf[9] == ']')
		return check_syscall(ctx, PRIV_HOOK_ANON_INODE,
				     PRIV_SC_IO_URING_SETUP, 0);
	// "[userfaultfd]"
	if (buf[0] == '[' && buf[1] == 'u' && buf[2] == 's' && buf[3] == 'e' &&
	    buf[4] == 'r' && buf[5] == 'f' && buf[12] == ']')
		return check_syscall(ctx, PRIV_HOOK_ANON_INODE,
				     PRIV_SC_USERFAULTFD, 0);
	return 0;
}

SEC("lsm/inode_init_security_anon")
int BPF_PROG(ig_priv_anon_inode, struct inode *inode, const struct qstr *name, const struct inode *context_inode, int ret)
{
	if (ret)
		return ret;
	return do_anon_inode(ctx, name);
}

/* ptrace */

static __always_inline int do_ptrace_access_check(void *ctx, unsigned int mode)
{
	enum priv_syscall sc = priv_syscall_from_nr(current_syscall_nr());
	struct priv_target t = { .sc = PRIV_SC_PTRACE, .cap = -1 };
	struct policy_match m = {};
	struct policy_value *header;
	__u64 cgid = 0;
	__u32 slot = 0;

	if (current_is_compat()) {
		// Read-mode /proc access (ps, top) is never ptrace.
		if (!(mode & PTRACE_MODE_ATTACH))
			return 0;
		// Unknown syscall: apply all three ptrace-family syscalls.
		header = priv_scope(&cgid, &slot);
		if (!header)
			return 0;
		resolve_syscall(slot, PRIV_SC_PTRACE, 0, &m);
		resolve_syscall(slot, PRIV_SC_PROCESS_VM_READV, 0, &m);
		resolve_syscall(slot, PRIV_SC_PROCESS_VM_WRITEV, 0, &m);
		return priv_verdict(ctx, PRIV_HOOK_PTRACE_ACCESS_CHECK, &t,
				    header, cgid, slot, &m);
	}

	switch (sc) {
	case PRIV_SC_PTRACE:
	case PRIV_SC_PROCESS_VM_READV:
	case PRIV_SC_PROCESS_VM_WRITEV:
		break;
	default:
		// /proc/<pid>/mem and similar attach-mode access count as
		// ptrace. Read-mode /proc access (ps, top) does not.
		if (!(mode & PTRACE_MODE_ATTACH))
			return 0;
		sc = PRIV_SC_PTRACE;
	}
	return check_syscall(ctx, PRIV_HOOK_PTRACE_ACCESS_CHECK, sc, 0);
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(ig_priv_ptrace, struct task_struct *child, unsigned int mode, int ret)
{
	if (ret)
		return ret;
	return do_ptrace_access_check(ctx, mode);
}

SEC("lsm/ptrace_traceme")
int BPF_PROG(ig_priv_traceme, struct task_struct *parent, int ret)
{
	if (ret)
		return ret;
	return check_syscall(ctx, PRIV_HOOK_PTRACE_TRACEME, PRIV_SC_PTRACE, 0);
}

/* Kernel modules and kexec */

static __always_inline int do_kernel_read_file(void *ctx, int id)
{
	enum priv_syscall sc = PRIV_SC_NONE;

	if (id == bpf_core_enum_value(enum kernel_read_file_id, READING_MODULE))
		sc = PRIV_SC_FINIT_MODULE;
	else if (id == bpf_core_enum_value(enum kernel_read_file_id,
					   READING_KEXEC_IMAGE) ||
		 id == bpf_core_enum_value(enum kernel_read_file_id,
					   READING_KEXEC_INITRAMFS))
		sc = PRIV_SC_KEXEC_LOAD;
	return check_syscall(ctx, PRIV_HOOK_KERNEL_READ_FILE, sc, 0);
}

SEC("lsm/kernel_read_file")
int BPF_PROG(ig_priv_kernel_read_file, struct file *file, int id, bool contents, int ret)
{
	if (ret)
		return ret;
	return do_kernel_read_file(ctx, id);
}

static __always_inline int do_kernel_load_data(void *ctx, int id)
{
	enum priv_syscall sc = PRIV_SC_NONE;

	if (id == bpf_core_enum_value(enum kernel_load_data_id, LOADING_MODULE))
		sc = PRIV_SC_INIT_MODULE;
	else if (id == bpf_core_enum_value(enum kernel_load_data_id,
					   LOADING_KEXEC_IMAGE))
		sc = PRIV_SC_KEXEC_LOAD;
	return check_syscall(ctx, PRIV_HOOK_KERNEL_LOAD_DATA, sc, 0);
}

SEC("lsm/kernel_load_data")
int BPF_PROG(ig_priv_kernel_load_data, int id, bool contents, int ret)
{
	if (ret)
		return ret;
	return do_kernel_load_data(ctx, id);
}

// An implicit module load requested on behalf of the task (for example an
// unknown socket family). It is judged as init_module.
SEC("lsm/kernel_module_request")
int BPF_PROG(ig_priv_module_request, char *kmod_name, int ret)
{
	if (ret)
		return ret;
	return check_syscall(ctx, PRIV_HOOK_KERNEL_MODULE_REQUEST,
			     PRIV_SC_INIT_MODULE, 0);
}

/* bpf, perf, keys, mknod */

SEC("lsm/bpf")
int BPF_PROG(ig_priv_bpf, int cmd, union bpf_attr *attr, unsigned int size, int ret)
{
	if (ret)
		return ret;
	return check_syscall(ctx, PRIV_HOOK_BPF, PRIV_SC_BPF, 0);
}

SEC("lsm/perf_event_open")
int BPF_PROG(ig_priv_perf_event_open, struct perf_event_attr *attr, int type, int ret)
{
	if (ret)
		return ret;
	return check_syscall(ctx, PRIV_HOOK_PERF_EVENT_OPEN,
			     PRIV_SC_PERF_EVENT_OPEN, 0);
}

SEC("lsm/key_alloc")
int BPF_PROG(ig_priv_key_alloc, struct key *key, const struct cred *cred, unsigned long flags, int ret)
{
	if (ret)
		return ret;
	return check_syscall(ctx, PRIV_HOOK_KEY_ALLOC, PRIV_SC_KEYCTL, 0);
}

SEC("lsm/key_permission")
int BPF_PROG(ig_priv_key_permission, key_ref_t key_ref, const struct cred *cred, unsigned int need_perm, int ret)
{
	if (ret)
		return ret;
	return check_syscall(ctx, PRIV_HOOK_KEY_PERMISSION, PRIV_SC_KEYCTL, 0);
}

// vfs_mknod also runs for bind(2) of a unix socket path and for overlayfs
// whiteouts (unlink or rename of a lower file). Judge only mknod(2) and
// mknodat(2). A 32-bit (compat) task's syscall number is not mapped, so for
// it every call is judged as mknod (fail closed), its unix socket bind(2)
// included.
SEC("lsm/inode_mknod")
int BPF_PROG(ig_priv_mknod, struct inode *dir, struct dentry *dentry, umode_t mode, unsigned int dev, int ret)
{
	if (ret)
		return ret;
	if (!current_is_compat() &&
	    priv_syscall_from_nr(current_syscall_nr()) != PRIV_SC_MKNOD)
		return 0;
	return check_syscall(ctx, PRIV_HOOK_INODE_MKNOD, PRIV_SC_MKNOD, 0);
}
