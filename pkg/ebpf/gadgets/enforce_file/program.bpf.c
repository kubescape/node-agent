// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Kubescape Authors

// enforce_file: enforce file access rules (read, write, create, delete,
// rename, chmod on path globs) for a set of containers with BPF LSM. The
// program is fixed; the policy is map data (file_policy.h), frozen per
// instance; a rule change starts a replacement instance.
//
// Hooks and access kinds:
// - file_open: read (FMODE_READ), write (FMODE_WRITE or O_TRUNC). A
//   read-write open judges both and keeps the most limiting verdict.
// - path_truncate: write. path_chmod, path_chown: chmod.
// - inode_setxattr (file capabilities), inode_set_acl (POSIX ACLs): chmod.
// - path_mknod (open with O_CREAT, mknod, mkfifo, AF_UNIX bind), path_mkdir,
//   path_symlink, path_link (new name): create. A create is denied here, not
//   at file_open, so a denied create leaves no empty file.
// - path_unlink, path_rmdir: delete.
// - path_rename: both names are judged as rename; the new name also as create
//   and write (a new name) or as write and delete (it replaces a file).
// - Move sources (the old name of a rename or a hard link, both names of
//   RENAME_EXCHANGE) are judged as rename, read and write with the full
//   decision, and against the move-source guard: the parent directories in
//   the patterns of deny rules of read or write. So a hard link or a rename
//   cannot give a file a name where it can be read or written when its own
//   name cannot. Both names of RENAME_EXCHANGE are also judged as write and
//   delete.
// - New names (of a rename, a hard link or a symbolic link; both names of
//   RENAME_EXCHANGE) are also judged against the new-name guard: the parent
//   directories in the patterns of deny rules of write or create. So a
//   directory cannot be moved onto the parent of a protected file. A hard
//   link's new name is a create and a write.
//
// Path source: bpf_d_path (the path from the task's root, so the container
// path). A task whose root is not the root of its mount (a chroot to a
// directory) gives paths that name other files: they count as unresolved.
// path_mknod cannot call bpf_d_path (6.8 and 6.12), the old name of a hard
// link has no struct path, and the inode hooks have no mount: they walk the
// dentries and mounts the same way d_path does. A path that cannot be
// resolved (error, longer than FILE_PATH_MAX, deeper than FILE_WALK_DEPTH)
// takes the most limiting rule or default of the access kind (fail closed).
//
// Not judged: tasks outside a bound cgroup, tasks not armed (see arming.h:
// the container runtime's own setup and exec helpers), and overlayfs'
// internal opens of the backing file (a private mount whose mnt_ns is
// MNT_NS_INTERNAL). A deny returns -EPERM only for an enforce deny.

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/macros.h>

// A subtree binding (a parent cgroup of containers) covers its descendant
// cgroups. Container bindings are exact.
#define BINDINGS_CGROUP_DEPTH 32
#define BINDINGS_DIRECT_LEVEL

// Prefix of the section's pinned maps (../common/pin.h).
#define SANDBOX_SECTION sbx1_file_
#include "../common/bindings.h"
#include "../common/slots.h"
#include "../common/arming.h"
#include "../common/verdict.h"
#include "file_policy.h"

// A key of SANDBOX_STORAGE (an unpublished slot) must miss file_slots.
_Static_assert(FILE_STORAGE == SANDBOX_STORAGE, "file_slots must hold exactly the storage buffers");

char LICENSE[] SEC("license") = "GPL";

GADGET_PARAM(host_mntns_id);
GADGET_PARAM(arming_fail_fork_marks);

// Before Linux 6.11 (no inode_xattr_skipcap hook), security_inode_setxattr
// runs cap_inode_setxattr (CAP_SYS_ADMIN for security.* names) only when the
// inode_setxattr hooks return 1. The owner sets this only before 6.9, where
// the verifier accepts it, so an allow returns 1 there. From 6.9 it stays 0:
// IMA and EVM run after BPF LSM and a return of 1 would skip them; from 6.11
// the capability check runs before the hooks; from 6.12 the verifier rejects
// a return of 1.
const volatile bool setxattr_allow_one = false;
GADGET_PARAM(setxattr_allow_one);

#define EPERM 1
#define ENOMEM 12
#define EINVAL 22
#define FILE_FMODE_READ 0x1
#define FILE_FMODE_WRITE 0x2
#define FILE_O_TRUNC 01000
#define FILE_RENAME_EXCHANGE (1 << 1)
#define OVERLAYFS_SUPER_MAGIC 0x794c7630
#define CLONE_INTO_CGROUP 0x200000000ULL

// Components walked from a dentry to the task's root; mount crossings count
// as steps too.
#define FILE_WALK_DEPTH 64

#define FILE_EVENT_PATH 512

enum file_hook : __u32 {
	FILE_HOOK_FILE_OPEN,
	FILE_HOOK_PATH_TRUNCATE,
	FILE_HOOK_PATH_MKNOD,
	FILE_HOOK_PATH_MKDIR,
	FILE_HOOK_PATH_SYMLINK,
	FILE_HOOK_PATH_LINK,
	FILE_HOOK_PATH_UNLINK,
	FILE_HOOK_PATH_RMDIR,
	FILE_HOOK_PATH_RENAME,
	FILE_HOOK_PATH_CHMOD,
	FILE_HOOK_PATH_CHOWN,
	FILE_HOOK_INODE_SETXATTR,
	FILE_HOOK_INODE_SET_ACL,
	// A root barrier denial (access_raw holds the barrier operation).
	FILE_HOOK_ROOT_BARRIER,
	// An operational fault (access_raw holds enum file_fault_kind).
	FILE_HOOK_FAULT,
};

enum file_fault_kind : __u32 {
	// A bound slot with no policy, or a task outside a Strict exact scope.
	FILE_FAULT_STRUCTURAL = 0,
	// A lost arming mark in a Strict binding.
	FILE_FAULT_TRACKING = 1,
};

struct event {
	VERDICT_BASE_FIELDS;
	__u32 host_pid;
	// Rule and origin ids of the deciding rule or default.
	__u32 rule_id;
	__u32 origin_id;
	// 1 when a default decided, not a rule.
	__u32 is_default;
	// Policy slot (combination of policies) of the bound container.
	__u32 slot;
	char comm[16];
	enum file_hook hook_raw;
	// The access kind that decided (move_source, new_name: a guard).
	enum file_access access_raw;
	// 1 when the file was a lower-layer (image) file.
	__u32 from_image;
	// The path that decided, as the container sees it; cut at
	// FILE_EVENT_PATH - 1 bytes; empty when it could not be resolved.
	char path[FILE_EVENT_PATH];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");
GADGET_TRACER(verdict, events, event);

// file_fault_report exports an operational fault as a file verdict (hook
// fault, the kind in access_raw): enforce when the hook denies, audit when it
// allows (an Audit binding, or an exec that cannot be refused). generation is
// the slot's, so the verdict is attributed to the slot's policies (0 when the
// slot has no policy).
static __always_inline void file_fault_report(__u64 cgid, __u32 slot,
					      __u64 generation, bool denied,
					      enum file_fault_kind kind)
{
	struct event *ev;

	if (denied)
		verdict_count(VERDICT_COUNT_DENIED);
	if (!verdict_report_allowed()) {
		verdict_count(VERDICT_COUNT_RATE_LIMITED);
		return;
	}
	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev) {
		verdict_count(VERDICT_COUNT_DROPPED);
		return;
	}
	__builtin_memset(ev, 0, sizeof(*ev));
	ev->generation = generation;
	ev->cgroup = cgid;
	ev->deny = 1;
	ev->mode = denied ? POLICY_MODE_ENFORCE : POLICY_MODE_AUDIT;
	ev->host_pid = bpf_get_current_pid_tgid() >> 32;
	ev->slot = slot;
	bpf_get_current_comm(ev->comm, sizeof(ev->comm));
	ev->hook_raw = FILE_HOOK_FAULT;
	ev->access_raw = kind;
	bpf_ringbuf_submit(ev, 0);
	verdict_count(VERDICT_COUNT_SUBMITTED);
}

// State of the dentry walk (file_resolve_walk).
struct file_walk_state {
	struct dentry *d;
	struct mount *m;
	struct dentry *root_d;
	struct vfsmount *root_m;
	__u32 pos; // first byte of the path written so far
	__u32 comps;
	__s32 done; // 1 resolved, -1 unresolved
	__u32 pad;
};

// Per-CPU scratch. owner is the task using it: another task that runs the
// program on this CPU while a hook is preempted changes it, and the hook then
// judges its path again. evowner is the task whose path is in evpath,
// written before the copy and checked after the event copies it.
struct file_scratch {
	char buf[FILE_BUF_SIZE + FILE_BUF_SLACK];
	char evpath[FILE_EVENT_PATH];
	struct file_match_state st;
	struct file_walk_state walk;
	struct file_bits matched;
	__u64 owner;
	__u64 evowner;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct file_scratch);
} file_scratch_buf SEC(".maps");

// One hook's evaluation: scope, then the most limiting verdict so far.
struct file_eval {
	const struct file_slot *s;
	struct file_scratch *x;
	__u64 cgid;
	__u64 me;
	// The binding's slot (events, fault counters).
	__u32 slot;
	__u32 access;
	__u32 from_image;
	// The binding flags (file_bound).
	__u32 flags;
	// A structural fault of a Strict binding (see file_bound): the hook
	// denies an armed task.
	bool fault;
	struct policy_match m;
	// The storage index of the slot's active publication: every policy
	// lookup of the call. Last, so the fields above keep their offsets (the
	// verifier's state pruning of the large hooks depends on them).
	__u32 storage;
};

/* Scope */

// file_fault records a structural fault: a section error, and for a Strict
// binding a slot fault and e->fault (the hook denies an armed task). An Audit
// binding allows.
static __always_inline void file_fault(struct file_eval *e, __u32 flags,
				       __u64 generation)
{
	bool strict = (flags & BINDING_STRICT) != 0;

	verdict_count(VERDICT_COUNT_SECTION_ERROR);
	// An unarmed task (the runtime's own setup) is never judged: no slot
	// fault, no event, no denial.
	if (!arming_task_armed(bpf_get_current_task_btf()))
		return;
	if (strict) {
		arming_slot_fault(e->slot);
		e->fault = true;
	}
	file_fault_report(e->cgid, e->slot, generation, strict,
			  FILE_FAULT_STRUCTURAL);
}

// file_bound looks up the task's binding and slot. A bound cgroup whose slot
// has no policy (never written: generation 0), or a task outside a Strict
// binding's exact scope, is a structural fault, not an unbound task.
static __always_inline bool file_bound(struct file_eval *e)
{
	const struct file_slot *s;
	__u32 flags = 0;

	if (!binding_lookup(&e->cgid, &e->slot, &flags))
		return false;
	e->flags = flags;
	e->storage = sandbox_slot_storage(e->slot);
	s = bpf_map_lookup_elem(&SANDBOX_MAP(file_slots), &e->storage);
	if (!s || !s->generation || (flags & BINDING_OUTSIDE_SCOPE)) {
		file_fault(e, flags, s ? s->generation : 0);
		return false;
	}
	if (s->mode == POLICY_MODE_OFF)
		return false;
	e->s = s;
	return true;
}

// file_armed completes the scope: the task is armed, scratch is ready.
static __always_inline bool file_armed(struct file_eval *e)
{
	__u32 zero = 0;

	if (!arming_task_armed(bpf_get_current_task_btf()))
		return false;
	// The scratch buffer is preallocated, so a miss is a fault too.
	e->x = bpf_map_lookup_elem(&file_scratch_buf, &zero);
	if (!e->x) {
		file_fault(e, e->flags, e->s ? e->s->generation : 0);
		return false;
	}
	e->me = bpf_get_current_pid_tgid();
	return true;
}

static __always_inline bool file_scope(struct file_eval *e)
{
	return file_bound(e) && file_armed(e);
}

// file_no_scope is the return value of a hook whose task is not judged: 0,
// or -EPERM for a structural fault of a Strict binding on an armed task (an
// unarmed task is the runtime's own setup, never judged).
static __always_inline int file_no_scope(const struct file_eval *e)
{
	volatile int result = 0;

	if (e->fault && arming_task_armed(bpf_get_current_task_btf()))
		result = -EPERM;
	return result;
}

static __always_inline struct mount *file_real_mount(struct vfsmount *mnt)
{
	return (void *)mnt - bpf_core_field_offset(struct mount, mnt);
}

// file_mnt_ns returns mount.mnt_ns of a vfsmount as a number (MNT_NS_INTERNAL
// is ERR_PTR(-EINVAL)), with one kernel read; 0 when the read fails.
static __always_inline long file_mnt_ns(struct vfsmount *mnt)
{
	long ns = 0;

	bpf_probe_read_kernel(&ns, sizeof(ns),
			      (void *)((unsigned long)mnt -
				       bpf_core_field_offset(struct mount, mnt) +
				       bpf_core_field_offset(struct mount, mnt_ns)));
	return ns;
}

// file_from_image is true for an overlay file with a lower-layer origin, so
// a copy-up (a write, chmod, touch or setxattr) does not change it. struct
// ovl_inode is private to overlayfs: right after its struct inode come
// __upperdentry and oe (struct ovl_entry *), whose first field is
// __numlower. The owner checks this layout in the kernel's BTF and sets
// FILE_SLOT_FROM_IMAGE only when it holds; oe is NULL for a file created in
// the upper layer.
static __always_inline bool file_from_image(const struct file_slot *s,
					    struct inode *inode)
{
	void *oe = NULL;
	__u32 numlower = 0;

	if (!(s->flags & FILE_SLOT_FROM_IMAGE) || !inode ||
	    BPF_CORE_READ(inode, i_sb, s_magic) != OVERLAYFS_SUPER_MAGIC)
		return false;
	if (bpf_probe_read_kernel(&oe, sizeof(oe),
				  (void *)inode + bpf_core_type_size(struct inode) +
					  sizeof(void *)) ||
	    !oe)
		return false;
	if (bpf_probe_read_kernel(&numlower, sizeof(numlower), oe))
		return false;
	return numlower > 0;
}

static __always_inline bool file_dentry_from_image(const struct file_slot *s,
						   struct dentry *d)
{
	return file_from_image(s, BPF_CORE_READ(d, d_inode));
}

#define PROC_SUPER_MAGIC 0x9fa0

// file_other_process is FILE_PROP_OTHER_PROCESS for a file of the
// /proc/<pid> (or /proc/<pid>/task/<tid>) directory of another thread group
// than the current task's, so /proc/self/environ and the task's own threads
// do not match a FILE_RULE_OTHER_PROCESS rule. struct proc_inode is private
// to procfs but in the kernel's BTF; its pid is NULL for files outside a
// process directory. The task that holds the pid is compared by tgid, which
// is the same process in every PID namespace. A pid without a task (the
// process exited) counts as another process.
static __always_inline __u32 file_other_process(struct inode *inode)
{
	struct proc_inode *pi;
	struct hlist_node *first;
	struct task_struct *t;
	struct pid *pid;

	if (!inode || BPF_CORE_READ(inode, i_sb, s_magic) != PROC_SUPER_MAGIC)
		return 0;
	pi = (void *)inode - bpf_core_field_offset(struct proc_inode, vfs_inode);
	pid = BPF_CORE_READ(pi, pid);
	if (!pid)
		return 0;
	first = BPF_CORE_READ(pid, tasks[PIDTYPE_PID].first);
	if (!first)
		return FILE_PROP_OTHER_PROCESS;
	t = (void *)first - bpf_core_field_offset(struct task_struct, pid_links);
	if (BPF_CORE_READ(t, tgid) == (__u32)(bpf_get_current_pid_tgid() >> 32))
		return 0;
	return FILE_PROP_OTHER_PROCESS;
}

// file_root_moved is true when the task's root is not the root of its mount
// (chroot to a directory). d_path then gives a path from that directory,
// which a rule for the full path does not match.
static __always_inline bool file_root_moved(void)
{
	struct task_struct *task = bpf_get_current_task_btf();

	return BPF_CORE_READ(task, fs, root.dentry) !=
	       BPF_CORE_READ(task, fs, root.mnt, mnt_root);
}

/* Path resolution: each returns the path length, or -1 (unresolved). */

static __always_inline long file_resolve_path(const struct path *path,
					      struct file_scratch *x,
					      __u32 *start)
{
	long n;

	*start = 0;
	if (file_root_moved())
		return -1;
	n = bpf_d_path((struct path *)path, x->buf, FILE_PATH_MAX + 1);
	if (n <= 0 || n > FILE_PATH_MAX + 1)
		return -1;
	return n - 1;
}

// file_resolve_dir_name resolves dir with bpf_d_path and appends the name of
// d, a dentry in dir.
static __always_inline long file_resolve_dir_name(const struct path *dir,
						  struct dentry *d,
						  struct file_scratch *x,
						  __u32 *start)
{
	long n = file_resolve_path(dir, x, start);
	const unsigned char *name;
	__u32 len, end;
	__u64 copy;

	if (n < 0)
		return -1;
	end = n;
	if (end != 1 || x->buf[0] != '/') {
		x->buf[end & FILE_BUF_MASK] = '/';
		end++;
	}
	len = BPF_CORE_READ(d, d_name.len);
	name = BPF_CORE_READ(d, d_name.name);
	if (len == 0 || len > FILE_NAME_MAX || end + len > FILE_PATH_MAX)
		return -1;
	copy = len;
	asm volatile("%0 &= 255" : "+r"(copy));
	if (bpf_probe_read_kernel(x->buf + (end & FILE_BUF_MASK), copy, name))
		return -1;
	return end + len;
}

// The walk keeps its state in the per-CPU scratch, not in the bpf_loop
// context on the stack, so the verifier sees unknown values and the
// callback's states converge.
struct file_walk_ctx {
	struct file_scratch *x;
};

static long file_walk_step(__u64 i, void *ctx)
{
	struct file_walk_state *w = &((struct file_walk_ctx *)ctx)->x->walk;
	char *buf = ((struct file_walk_ctx *)ctx)->x->buf;
	struct dentry *d = w->d;
	struct mount *m = w->m;
	struct vfsmount *vm = (void *)m + bpf_core_field_offset(struct mount, mnt);
	const unsigned char *name;
	struct dentry *parent;
	__u32 len, pos;
	__u64 copy;

	if (d == w->root_d && vm == w->root_m) {
		w->done = 1;
		return 1;
	}
	if (d == BPF_CORE_READ(vm, mnt_root)) {
		struct mount *pm = BPF_CORE_READ(m, mnt_parent);

		// A namespace root that is not the task's root: d_path also
		// stops here.
		if (pm == m) {
			w->done = 1;
			return 1;
		}
		w->d = BPF_CORE_READ(m, mnt_mountpoint);
		w->m = pm;
		return 0;
	}
	parent = BPF_CORE_READ(d, d_parent);
	if (parent == d) {
		w->done = 1;
		return 1;
	}
	len = BPF_CORE_READ(d, d_name.len);
	name = BPF_CORE_READ(d, d_name.name);
	pos = w->pos;
	if (len == 0 || len > FILE_NAME_MAX || w->comps >= FILE_WALK_DEPTH ||
	    pos < FILE_BUF_SIZE - 1 - FILE_PATH_MAX + len + 1) {
		w->done = -1;
		return 1;
	}
	pos -= len;
	copy = len;
	asm volatile("%0 &= 255" : "+r"(copy));
	if (bpf_probe_read_kernel(buf + (pos & FILE_BUF_MASK), copy, name)) {
		w->done = -1;
		return 1;
	}
	pos--;
	buf[pos & FILE_BUF_MASK] = '/';
	w->pos = pos;
	w->comps++;
	w->d = parent;
	return 0;
}

// file_resolve_walk builds the path of d on mount mnt by walking the
// dentries and mounts up to the task's root, as d_path does (without its
// rename and mount sequence locks). The path ends at FILE_BUF_SIZE - 1.
static __always_inline long file_resolve_walk(struct dentry *d,
					      struct vfsmount *mnt,
					      struct file_scratch *x,
					      __u32 *start)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct file_walk_state *w = &x->walk;
	struct file_walk_ctx c = { .x = x };
	struct vfsmount *root_m;
	__u32 pos;

	w->d = d;
	w->m = file_real_mount(mnt);
	w->root_d = BPF_CORE_READ(task, fs, root.dentry);
	root_m = BPF_CORE_READ(task, fs, root.mnt);
	w->root_m = root_m;
	// A chroot to a directory (see file_root_moved).
	if (w->root_d != BPF_CORE_READ(root_m, mnt_root))
		return -1;
	w->pos = FILE_BUF_SIZE - 1;
	w->comps = 0;
	w->done = 0;
	x->buf[FILE_BUF_SIZE - 1] = 0;
	bpf_loop(FILE_WALK_DEPTH * 2, file_walk_step, &c, 0);
	if (w->done != 1)
		return -1;
	pos = w->pos;
	if (pos >= FILE_BUF_SIZE - 1) {
		pos = FILE_BUF_SIZE - 2;
		x->buf[pos] = '/';
	}
	if (pos < FILE_BUF_SIZE - 1 - FILE_PATH_MAX)
		return -1;
	*start = pos;
	return FILE_BUF_SIZE - 1 - pos;
}

/* Judgement */

// file_take keeps m when it is more limiting, with its access kind and path.
static __always_inline void file_take(struct file_eval *e,
				      const struct policy_match *m,
				      __u32 access, __u32 props,
				      __u32 start, long len)
{
	if (m->rank <= e->m.rank)
		return;
	e->m = *m;
	e->access = access;
	e->from_image = props & FILE_PROP_FROM_IMAGE;
	if (m->rank < POLICY_RANK_DENY_AUDIT)
		return;
	e->x->evowner = e->me;
	e->x->evpath[0] = 0;
	if (len <= 0)
		return;
	if (bpf_probe_read_kernel(e->x->evpath, FILE_EVENT_PATH - 1,
				  e->x->buf + (start & FILE_BUF_MASK)))
		return;
	e->x->evpath[len < FILE_EVENT_PATH - 1 ? len : FILE_EVENT_PATH - 1] = 0;
}

// file_judge_mask judges one resolved path (len < 0: unresolved) for every
// access kind in mask (bits of enum file_access). It returns false, without
// a verdict, when another task used the scratch meanwhile and this is not
// the last try; on the last try that path counts as unresolved.
static __always_inline bool file_judge_mask(struct file_eval *e, long len,
					    __u32 start, __u32 mask,
					    __u32 props, bool last)
{
	struct policy_match best = {};
	__u32 best_access = 0;
	bool resolved = len >= 0;

	if (resolved) {
		file_match(e->s, e->storage, e->x->buf, start, len, &e->x->st,
			   &e->x->matched);
		file_decide_mask(e->s, mask, &e->x->matched, props, &best,
				 &best_access);
	}
	if (e->x->owner != e->me) {
		if (!last)
			return false;
		verdict_count(VERDICT_COUNT_SECTION_ERROR);
		resolved = false;
	}
	if (!resolved) {
		best.rank = 0;
		for (__u32 a = 0; a <= FILE_ACCESS_NEW_NAME; a++) {
			struct policy_match m = {};

			if (!(mask & (1U << a)))
				continue;
			file_unresolved(e->s, a, props, &m);
			if (m.rank > best.rank) {
				best = m;
				best_access = a;
			}
		}
		len = -1;
	}
	file_take(e, &best, best_access, props, start, len);
	return true;
}

// FILE_JUDGE resolves a path with RESOLVE (which sets _start) and judges it
// for the access kinds in MASK; a second try follows when another task used
// the per-CPU scratch meanwhile.
#define FILE_JUDGE(e, RESOLVE, MASK, PROPS)                                    \
	do {                                                                   \
		for (int _try = 0; _try < 2; _try++) {                         \
			__u32 _start = 0;                                      \
			long _len;                                             \
			(e)->x->owner = (e)->me;                               \
			_len = (RESOLVE);                                      \
			if (file_judge_mask(e, _len, _start, MASK, PROPS,      \
					    _try == 1))                        \
				break;                                         \
		}                                                              \
	} while (0)

#define BIT(a) (1U << (a))

static __always_inline int file_verdict(enum file_hook hook,
					struct file_eval *e)
{
	const struct policy_match *m = &e->m;
	struct event *ev;
	bool reporting;

	if (m->rank < POLICY_RANK_DENY_AUDIT) {
		verdict_count(VERDICT_COUNT_ALLOWED);
		return 0;
	}
	verdict_count(VERDICT_COUNT_DENIED);

	reporting = verdict_report_allowed();
	ev = reporting ? bpf_ringbuf_reserve(&events, sizeof(*ev), 0) : NULL;
	if (ev) {
		__builtin_memset(ev, 0, sizeof(*ev));
		VERDICT_FILL_BASE(ev, m, e->s->generation, e->cgid);
		ev->host_pid = bpf_get_current_pid_tgid() >> 32;
		ev->rule_id = m->rule_id;
		ev->origin_id = m->origin_id;
		ev->is_default = m->is_default;
		ev->slot = e->slot;
		bpf_get_current_comm(ev->comm, sizeof(ev->comm));
		ev->hook_raw = hook;
		ev->access_raw = e->access;
		ev->from_image = e->from_image;
		bpf_probe_read_kernel_str(ev->path, sizeof(ev->path),
					  e->x->evpath);
		// Another task on this CPU wrote its own path meanwhile: the
		// event keeps the verdict and loses the path.
		if (e->x->evowner != e->me)
			ev->path[0] = 0;
		bpf_ringbuf_submit(ev, 0);
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

/* Hooks */

// ret, the last argument of an int hook, is the verdict of the BPF LSM
// programs that ran before this one. The kernel already keeps an earlier deny:
// the trampoline runs no later program after a nonzero return, so ret is 0
// here (kernel test TestGadgetEarlierBPFDeny). FILE_KEEP_DENY is a second
// guard: a negative ret is returned unchanged, before any judging. ret is
// read by position; the argument count of every hook below is the same from
// Linux 6.2 to 6.18. The range check keeps the return value in the
// verifier's [-MAX_ERRNO, 0].
#define FILE_MAX_ERRNO 4095
#define FILE_KEEP_DENY(ret)                                                    \
	do {                                                                   \
		if ((ret) < 0)                                                 \
			return (ret) >= -FILE_MAX_ERRNO ? (ret) : -EPERM;      \
	} while (0)

// Order in every hook: earlier deny, (file_open: overlay internal open),
// binding, arming, path, match. Unbound tasks leave after one hash lookup per
// cgroup level.
SEC("lsm/file_open")
int BPF_PROG(ig_file_open, struct file *file, int ret)
{
	struct file_eval e = {};
	__u32 fmode, mask = 0, props;
	struct inode *inode;

	FILE_KEEP_DENY(ret);

	// overlayfs opens the backing file on a private clone mount
	// (clone_private_mount: mnt_ns = MNT_NS_INTERNAL = ERR_PTR(-EINVAL));
	// user space cannot create such a mount. Copy-up opens use it too.
	// Checked first: every open of an overlay file calls this hook twice,
	// and the backing call then skips the binding lookup. file is a trusted
	// argument, so f_path.mnt is a direct load; mnt_ns takes one read.
	if (file_mnt_ns(file->f_path.mnt) == -EINVAL)
		return 0;
	if (!file_bound(&e))
		return file_no_scope(&e);
	if (!file_armed(&e))
		return file_no_scope(&e);
	fmode = BPF_CORE_READ(file, f_mode);
	if (fmode & FILE_FMODE_READ)
		mask |= BIT(FILE_ACCESS_READ);
	if ((fmode & FILE_FMODE_WRITE) ||
	    (BPF_CORE_READ(file, f_flags) & FILE_O_TRUNC))
		mask |= BIT(FILE_ACCESS_WRITE);
	if (!mask)
		return 0;
	inode = BPF_CORE_READ(file, f_inode);
	props = file_from_image(e.s, inode) ? FILE_PROP_FROM_IMAGE : 0;
	props |= file_other_process(inode);
	FILE_JUDGE(&e, file_resolve_path(&file->f_path, e.x, &_start), mask,
		   props);
	return file_verdict(FILE_HOOK_FILE_OPEN, &e);
}

SEC("lsm/path_truncate")
int BPF_PROG(ig_file_truncate, const struct path *path, int ret)
{
	struct file_eval e = {};
	bool fi;

	FILE_KEEP_DENY(ret);
	if (!file_scope(&e))
		return file_no_scope(&e);
	fi = file_dentry_from_image(e.s, BPF_CORE_READ(path, dentry));
	FILE_JUDGE(&e, file_resolve_path(path, e.x, &_start),
		   BIT(FILE_ACCESS_WRITE), fi);
	return file_verdict(FILE_HOOK_PATH_TRUNCATE, &e);
}

static __always_inline int file_attr(enum file_hook hook,
				     const struct path *path)
{
	struct file_eval e = {};
	bool fi;

	if (!file_scope(&e))
		return file_no_scope(&e);
	fi = file_dentry_from_image(e.s, BPF_CORE_READ(path, dentry));
	FILE_JUDGE(&e, file_resolve_path(path, e.x, &_start),
		   BIT(FILE_ACCESS_CHMOD), fi);
	return file_verdict(hook, &e);
}

SEC("lsm/path_chmod")
int BPF_PROG(ig_file_chmod, const struct path *path, umode_t mode, int ret)
{
	FILE_KEEP_DENY(ret);
	return file_attr(FILE_HOOK_PATH_CHMOD, path);
}

SEC("lsm/path_chown")
int BPF_PROG(ig_file_chown, const struct path *path, __u32 uid, __u32 gid,
	     int ret)
{
	FILE_KEEP_DENY(ret);
	return file_attr(FILE_HOOK_PATH_CHOWN, path);
}

// file_inode_attr judges a change of what a file allows through an extended
// attribute (a file capability, a POSIX ACL) as chmod. These hooks have a
// dentry and no mount. A dentry on the super block of the task's root mount
// (which must be that super block's root) gets its path by the walk from
// that mount. overlayfs repeats the change on the inode of its upper file
// system, and copies a file's attributes up the same way, with its mounter's
// credentials: that call is not judged (the overlay call was). Any other
// dentry (a volume) is an unresolved path.
static __always_inline int file_inode_attr(enum file_hook hook,
					   struct dentry *dentry)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct file_eval e = {};
	struct super_block *sb;
	struct vfsmount *root;
	bool fi;

	if (!file_scope(&e))
		return file_no_scope(&e);
	root = BPF_CORE_READ(task, fs, root.mnt);
	sb = BPF_CORE_READ(root, mnt_sb);
	if (BPF_CORE_READ(dentry, d_sb) == sb &&
	    BPF_CORE_READ(root, mnt_root) == BPF_CORE_READ(sb, s_root)) {
		fi = file_dentry_from_image(e.s, dentry);
		FILE_JUDGE(&e, file_resolve_walk(dentry, root, e.x, &_start),
			   BIT(FILE_ACCESS_CHMOD), fi);
		return file_verdict(hook, &e);
	}
	if (BPF_CORE_READ(sb, s_magic) == OVERLAYFS_SUPER_MAGIC &&
	    BPF_CORE_READ(task, cred) != BPF_CORE_READ(task, real_cred))
		return 0;
	FILE_JUDGE(&e, -1, BIT(FILE_ACCESS_CHMOD), false);
	return file_verdict(hook, &e);
}

// POSIX ACLs go to inode_set_acl (Linux 6.2 and later), not here. An earlier
// ret of 1 (allow, then the capability check) stays 1 when setxattr_allow_one
// is set, and a deny of this gadget replaces it.
SEC("lsm/inode_setxattr")
int BPF_PROG(ig_file_setxattr, void *idmap, struct dentry *dentry,
	     const char *name, const void *value, size_t size, int flags,
	     int ret)
{
	char n[32];
	int r = 0;

	FILE_KEEP_DENY(ret);
	if (bpf_probe_read_kernel_str(n, sizeof(n), name) <= 0 ||
	    !bpf_strncmp(n, sizeof(n), "security.capability"))
		r = file_inode_attr(FILE_HOOK_INODE_SETXATTR, dentry);
	if (r)
		return r;
	if (setxattr_allow_one)
		return 1;
	return 0;
}

SEC("lsm/inode_set_acl")
int BPF_PROG(ig_file_set_acl, void *idmap, struct dentry *dentry,
	     const char *acl_name, void *kacl, int ret)
{
	FILE_KEEP_DENY(ret);
	return file_inode_attr(FILE_HOOK_INODE_SET_ACL, dentry);
}

// bpf_d_path is not allowed in path_mknod: the new name is resolved by the
// walk from its (negative) dentry, on the directory's mount.
SEC("lsm/path_mknod")
int BPF_PROG(ig_file_mknod, const struct path *dir, struct dentry *dentry,
	     umode_t mode, unsigned int dev, int ret)
{
	struct file_eval e = {};

	FILE_KEEP_DENY(ret);
	if (!file_scope(&e))
		return file_no_scope(&e);
	FILE_JUDGE(&e,
		   file_resolve_walk(dentry, BPF_CORE_READ(dir, mnt), e.x,
				     &_start),
		   BIT(FILE_ACCESS_CREATE), false);
	return file_verdict(FILE_HOOK_PATH_MKNOD, &e);
}

static __always_inline int file_dir_entry(enum file_hook hook,
					  const struct path *dir,
					  struct dentry *dentry, __u32 mask)
{
	struct file_eval e = {};
	bool fi = false;

	if (!file_scope(&e))
		return file_no_scope(&e);
	if (mask & BIT(FILE_ACCESS_DELETE))
		fi = file_dentry_from_image(e.s, dentry);
	FILE_JUDGE(&e, file_resolve_dir_name(dir, dentry, e.x, &_start), mask,
		   fi);
	return file_verdict(hook, &e);
}

SEC("lsm/path_mkdir")
int BPF_PROG(ig_file_mkdir, const struct path *dir, struct dentry *dentry,
	     umode_t mode, int ret)
{
	FILE_KEEP_DENY(ret);
	return file_dir_entry(FILE_HOOK_PATH_MKDIR, dir, dentry,
			      BIT(FILE_ACCESS_CREATE));
}

// A symbolic link named like a guarded parent would point that directory
// elsewhere.
SEC("lsm/path_symlink")
int BPF_PROG(ig_file_symlink, const struct path *dir, struct dentry *dentry,
	     const char *old_name, int ret)
{
	FILE_KEEP_DENY(ret);
	return file_dir_entry(FILE_HOOK_PATH_SYMLINK, dir, dentry,
			      BIT(FILE_ACCESS_CREATE) |
				      FILE_NEW_NAME_GUARD_MASK);
}

SEC("lsm/path_unlink")
int BPF_PROG(ig_file_unlink, const struct path *dir, struct dentry *dentry,
	     int ret)
{
	FILE_KEEP_DENY(ret);
	return file_dir_entry(FILE_HOOK_PATH_UNLINK, dir, dentry,
			      BIT(FILE_ACCESS_DELETE));
}

SEC("lsm/path_rmdir")
int BPF_PROG(ig_file_rmdir, const struct path *dir, struct dentry *dentry,
	     int ret)
{
	FILE_KEEP_DENY(ret);
	return file_dir_entry(FILE_HOOK_PATH_RMDIR, dir, dentry,
			      BIT(FILE_ACCESS_DELETE));
}

// A hard link: the new name is a create and a write, and a new name for the
// guard; the old name is a move source (FILE_MOVE_SOURCE_MASK). Both names
// are on new_dir's mount (the kernel refuses a link across mounts).
SEC("lsm/path_link")
int BPF_PROG(ig_file_link, struct dentry *old_dentry, const struct path *new_dir,
	     struct dentry *new_dentry, int ret)
{
	struct file_eval e = {};
	bool fi;

	FILE_KEEP_DENY(ret);
	if (!file_scope(&e))
		return file_no_scope(&e);
	FILE_JUDGE(&e, file_resolve_dir_name(new_dir, new_dentry, e.x, &_start),
		   FILE_NEW_FILE_MASK | FILE_NEW_NAME_GUARD_MASK, false);
	fi = file_dentry_from_image(e.s, old_dentry);
	FILE_JUDGE(&e,
		   file_resolve_walk(old_dentry, BPF_CORE_READ(new_dir, mnt),
				     e.x, &_start),
		   FILE_MOVE_SOURCE_MASK, fi);
	return file_verdict(FILE_HOOK_PATH_LINK, &e);
}

SEC("lsm/path_rename")
int BPF_PROG(ig_file_rename, const struct path *old_dir,
	     struct dentry *old_dentry, const struct path *new_dir,
	     struct dentry *new_dentry, unsigned int flags, int ret)
{
	struct file_eval e = {};
	__u32 old_mask = FILE_MOVE_SOURCE_MASK;
	__u32 new_mask = BIT(FILE_ACCESS_RENAME) | FILE_NEW_NAME_GUARD_MASK;
	bool fi;

	FILE_KEEP_DENY(ret);
	if (!file_scope(&e))
		return file_no_scope(&e);
	// An exchange moves both files and replaces both names: both are new
	// names.
	if (flags & FILE_RENAME_EXCHANGE)
		old_mask |= FILE_REPLACED_MASK | FILE_NEW_NAME_GUARD_MASK;
	fi = file_dentry_from_image(e.s, old_dentry);
	FILE_JUDGE(&e, file_resolve_dir_name(old_dir, old_dentry, e.x, &_start),
		   old_mask, fi);
	fi = false;
	if (flags & FILE_RENAME_EXCHANGE) {
		new_mask = old_mask;
		fi = file_dentry_from_image(e.s, new_dentry);
	} else if (BPF_CORE_READ(new_dentry, d_inode)) {
		new_mask |= FILE_REPLACED_MASK;
		fi = file_dentry_from_image(e.s, new_dentry);
	} else {
		new_mask |= FILE_NEW_FILE_MASK;
	}
	FILE_JUDGE(&e, file_resolve_dir_name(new_dir, new_dentry, e.x, &_start),
		   new_mask, fi);
	return file_verdict(FILE_HOOK_PATH_RENAME, &e);
}

/* Arming */

// file_active returns the header of the slot's active publication, or NULL.
static __always_inline const struct file_slot *file_active(__u32 slot)
{
	__u32 storage = sandbox_slot_storage(slot);

	return bpf_map_lookup_elem(&SANDBOX_MAP(file_slots), &storage);
}

// file_strict_binding returns true, with the slot and the binding flags,
// when a Strict binding covers the current task: its class (BINDING_STRICT),
// or a slot whose mode enforces, so an owner that sets no class never makes a
// fault path allow.
static __always_inline bool file_strict_binding(__u64 *cgid, __u32 *slot,
						__u32 *flags)
{
	const struct file_slot *s;

	if (!binding_lookup(cgid, slot, flags))
		return false;
	if (*flags & BINDING_STRICT)
		return true;
	s = file_active(*slot);
	return s && s->mode == POLICY_MODE_ENFORCE;
}

// file_slot_generation is the generation of the slot's active publication,
// or 0 when it has none.
static __always_inline __u64 file_slot_generation(__u32 slot)
{
	const struct file_slot *s = file_active(slot);

	return s ? s->generation : 0;
}

// The exec hook cannot fail the exec (a void hook: no verdict, no ret). A
// lost mark in an enforcing slot is a tracking fault: the owner reports the
// binding as not confirmed.
SEC("lsm/bprm_committed_creds")
int BPF_PROG(ig_file_exec)
{
	__u32 slot = 0, flags = 0;
	__u64 cgid = 0;
	bool strict = file_strict_binding(&cgid, &slot, &flags);

	if (!arming_on_exec(flags)) {
		verdict_count(VERDICT_COUNT_SECTION_ERROR);
		if (strict) {
			// Counted and reported; the exec itself cannot fail.
			arming_slot_fault(slot);
			file_fault_report(cgid, slot, file_slot_generation(slot),
					  false, FILE_FAULT_TRACKING);
		}
	}
	return 0;
}

/* Root barrier */

// The root barrier (../common/root_barrier.h) covers every armed task of a
// Strict binding, in the bound cgroup or (as a Strict fault) in a child cgroup
// outside its exact scope. Such a task cannot chroot, pivot_root, create a
// user namespace, create or join a mount namespace, or change the mount tree,
// so the paths it opens stay the paths the rules name. This holds whatever
// the privilege section says: a Strict file section denies these operations
// even where a privilege rule only audits them. Tasks of an Audit binding are
// not covered: audit stays non-blocking. Unarmed tasks (the runtime's own
// setup) are not covered either. A bound cgroup whose slot has no policy is a
// fault: denied under Strict, allowed and counted under Audit. The owner
// attests the barrier at Ready (rootbarrier.Verify). Every denial is exported
// as a file verdict (FILE_HOOK_ROOT_BARRIER).
#define FILE_BARRIER_NOT 0
#define FILE_BARRIER_YES 1
#define FILE_BARRIER_FAULT_STRICT 2
#define FILE_BARRIER_FAULT_AUDIT 3

static __always_inline __u64 file_barrier_coverage(struct task_struct *task)
{
	const struct file_slot *s;
	__u32 slot = 0, flags = 0;
	__u64 cgid = 0;

	if (!arming_task_armed(task) || !binding_lookup(&cgid, &slot, &flags))
		return FILE_BARRIER_NOT;
	s = file_active(slot);
	if (!s || !s->generation)
		return (flags & BINDING_STRICT) ? FILE_BARRIER_FAULT_STRICT :
						  FILE_BARRIER_FAULT_AUDIT;
	if ((flags & BINDING_STRICT) || s->mode == POLICY_MODE_ENFORCE)
		return FILE_BARRIER_YES;
	return FILE_BARRIER_NOT;
}

// file_barrier_report exports a barrier denial as a file verdict: enforce,
// no rule (the reason is the barrier), the barrier operation in access_raw.
static __always_inline void file_barrier_report(__u32 op)
{
	const struct file_slot *s;
	struct event *ev;
	__u32 slot = 0, flags = 0;
	__u64 cgid = 0;

	verdict_count(VERDICT_COUNT_DENIED);
	if (!verdict_report_allowed()) {
		verdict_count(VERDICT_COUNT_RATE_LIMITED);
		return;
	}
	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev) {
		verdict_count(VERDICT_COUNT_DROPPED);
		return;
	}
	__builtin_memset(ev, 0, sizeof(*ev));
	binding_lookup(&cgid, &slot, &flags);
	s = file_active(slot);
	ev->generation = s ? s->generation : 0;
	ev->cgroup = cgid;
	ev->deny = 1;
	ev->mode = POLICY_MODE_ENFORCE;
	ev->host_pid = bpf_get_current_pid_tgid() >> 32;
	ev->slot = slot;
	bpf_get_current_comm(ev->comm, sizeof(ev->comm));
	ev->hook_raw = FILE_HOOK_ROOT_BARRIER;
	ev->access_raw = op;
	bpf_ringbuf_submit(ev, 0);
	verdict_count(VERDICT_COUNT_SUBMITTED);
}

// ig_file_alloc carries the barrier's task_alloc body, first, so the
// barrier denies before the arming mark is allocated (two programs on one
// hook have no fixed order).
#define ROOT_BARRIER_NO_TASK_ALLOC_PROGRAM
#define ROOT_BARRIER_COVERED(task) file_barrier_coverage(task)
#define ROOT_BARRIER_ON_DENY(ctx, op, arg) file_barrier_report(op)
#include "../common/root_barrier.h"

_Static_assert(FILE_BARRIER_NOT == ROOT_BARRIER_TASK_NOT_COVERED, "coverage value");
_Static_assert(FILE_BARRIER_YES == ROOT_BARRIER_TASK_COVERED, "coverage value");
_Static_assert(FILE_BARRIER_FAULT_STRICT == ROOT_BARRIER_TASK_FAULT_STRICT, "coverage value");
_Static_assert(FILE_BARRIER_FAULT_AUDIT == ROOT_BARRIER_TASK_FAULT_AUDIT, "coverage value");

// An armed parent whose child could not be marked: an unmarked child would
// escape every rule, so a Strict binding refuses the fork and counts a slot
// fault. Audit never blocks, even on a fault: an Audit binding or an unbound
// cgroup allows the fork. A clone into another cgroup (CLONE_INTO_CGROUP) can
// start the child in a Strict cgroup, so it counts a node fault, which the
// owner reports against every Strict binding.
SEC("lsm/task_alloc")
int BPF_PROG(ig_file_alloc, struct task_struct *task,
	     unsigned long clone_flags, int ret)
{
	__u32 slot = 0, flags = 0;
	__u64 cgid = 0;

	FILE_KEEP_DENY(ret);
	ret = root_barrier_task_alloc(ctx, clone_flags);
	if (ret)
		return ret;
	if (arming_on_fork(task, clone_flags))
		return 0;
	verdict_count(VERDICT_COUNT_SECTION_ERROR);
	if (file_strict_binding(&cgid, &slot, &flags)) {
		arming_slot_fault(slot);
		file_fault_report(cgid, slot, file_slot_generation(slot), true,
				  FILE_FAULT_TRACKING);
		return -ENOMEM;
	}
	if ((__u64)clone_flags & CLONE_INTO_CGROUP)
		arming_witness_count(ARMING_WITNESS_NODE_FAULT);
	return 0;
}
