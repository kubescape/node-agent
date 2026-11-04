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
// - path_mknod (open with O_CREAT, mknod, mkfifo, AF_UNIX bind), path_mkdir,
//   path_symlink, path_link (new name): create. A create is denied here, not
//   at file_open, so a denied create leaves no empty file.
// - path_unlink, path_rmdir: delete.
// - path_rename: both names are judged as rename; the new name also as create
//   (a new name) or as write and delete (it replaces a file).
// - Move sources (the old name of a rename or a hard link, both names of
//   RENAME_EXCHANGE) are also judged against the guard of every deny rule:
//   its paths and their parent directories. So a hard link or a rename cannot
//   give a protected file a second, unprotected name.
//
// Path source: bpf_d_path (the path from the task's root, so the container
// path). path_mknod cannot call bpf_d_path (6.8 and 6.12), and the old name
// of a hard link has no struct path: both walk the dentries and mounts the
// same way d_path does. A path that cannot be resolved (error, longer than
// FILE_PATH_MAX, deeper than FILE_WALK_DEPTH) takes the most limiting rule or
// default of the access kind (fail closed).
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

// A task that moves into a child cgroup of its container stays covered, up to
// this many levels below the bound cgroup.
#define BINDINGS_CGROUP_DEPTH 32

#include "../common/arming.h"
#include "../common/bindings.h"
#include "../common/verdict.h"
#include "file_policy.h"

char LICENSE[] SEC("license") = "GPL";

GADGET_PARAM(host_mntns_id);
GADGET_PARAM(arming_fail_fork_marks);

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
	// The access kind that decided (move_source: the guard).
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
// judges its path again.
struct file_scratch {
	char buf[FILE_BUF_SIZE + FILE_BUF_SLACK];
	char evpath[FILE_EVENT_PATH];
	struct file_match_state st;
	struct file_walk_state walk;
	struct file_bits matched;
	__u64 owner;
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
	__u32 slot;
	__u32 access;
	__u32 from_image;
	struct policy_match m;
};

/* Scope */

// file_bound looks up the task's binding and slot.
static __always_inline bool file_bound(struct file_eval *e)
{
	if (!binding_lookup(&e->cgid, &e->slot))
		return false;
	e->s = file_slot_get(e->slot);
	return e->s != NULL;
}

// file_armed completes the scope: the task is armed, scratch is ready.
static __always_inline bool file_armed(struct file_eval *e)
{
	__u32 zero = 0;

	if (!arming_task_armed(bpf_get_current_task_btf()))
		return false;
	e->x = bpf_map_lookup_elem(&file_scratch_buf, &zero);
	if (!e->x)
		return false;
	e->me = bpf_get_current_pid_tgid();
	return true;
}

static __always_inline bool file_scope(struct file_eval *e)
{
	return file_bound(e) && file_armed(e);
}

static __always_inline struct mount *file_real_mount(struct vfsmount *mnt)
{
	return (void *)mnt - bpf_core_field_offset(struct mount, mnt);
}

// file_from_image is true for a file of an overlay lower layer that this
// container has not copied up: ovl_inode.__upperdentry, the field right
// after the overlay inode's struct inode, is NULL.
static __always_inline bool file_from_image(struct inode *inode)
{
	struct dentry *upper = NULL;

	if (!inode || BPF_CORE_READ(inode, i_sb, s_magic) != OVERLAYFS_SUPER_MAGIC)
		return false;
	if (bpf_probe_read_kernel(&upper, sizeof(upper),
				  (void *)inode + bpf_core_type_size(struct inode)))
		return false;
	return upper == NULL;
}

static __always_inline bool file_dentry_from_image(struct dentry *d)
{
	return file_from_image(BPF_CORE_READ(d, d_inode));
}

/* Path resolution: each returns the path length, or -1 (unresolved). */

static __always_inline long file_resolve_path(const struct path *path,
					      struct file_scratch *x,
					      __u32 *start)
{
	long n = bpf_d_path((struct path *)path, x->buf, FILE_PATH_MAX + 1);

	*start = 0;
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
	__u32 pos;

	w->d = d;
	w->m = file_real_mount(mnt);
	w->root_d = BPF_CORE_READ(task, fs, root.dentry);
	w->root_m = BPF_CORE_READ(task, fs, root.mnt);
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
				      __u32 access, bool from_image,
				      __u32 start, long len)
{
	if (m->rank <= e->m.rank)
		return;
	e->m = *m;
	e->access = access;
	e->from_image = from_image;
	if (m->rank < POLICY_RANK_DENY_AUDIT)
		return;
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
					    bool from_image, bool last)
{
	struct policy_match best = {};
	__u32 best_access = 0;
	bool resolved = len >= 0;

	if (resolved)
		file_match(e->s, e->slot, e->x->buf, start, len, &e->x->st,
			   &e->x->matched);
	for (__u32 a = 0; a <= FILE_ACCESS_MOVE_SOURCE; a++) {
		struct policy_match m = {};

		if (!(mask & (1U << a)))
			continue;
		if (resolved)
			file_decide(e->s, a, &e->x->matched, from_image, &m);
		else
			file_unresolved(e->s, a, &m);
		if (m.rank > best.rank) {
			best = m;
			best_access = a;
		}
	}
	if (e->x->owner != e->me) {
		if (!last)
			return false;
		verdict_count(VERDICT_COUNT_SECTION_ERROR);
		best.rank = 0;
		for (__u32 a = 0; a <= FILE_ACCESS_MOVE_SOURCE; a++) {
			struct policy_match m = {};

			if (!(mask & (1U << a)))
				continue;
			file_unresolved(e->s, a, &m);
			if (m.rank > best.rank) {
				best = m;
				best_access = a;
			}
		}
		len = -1;
	}
	file_take(e, &best, best_access, from_image, start, len);
	return true;
}

// FILE_JUDGE resolves a path with RESOLVE (which sets _start) and judges it
// for the access kinds in MASK; a second try follows when another task used
// the per-CPU scratch meanwhile.
#define FILE_JUDGE(e, RESOLVE, MASK, FROM_IMAGE)                               \
	do {                                                                   \
		for (int _try = 0; _try < 2; _try++) {                         \
			__u32 _start = 0;                                      \
			long _len;                                             \
			(e)->x->owner = (e)->me;                               \
			_len = (RESOLVE);                                      \
			if (file_judge_mask(e, _len, _start, MASK, FROM_IMAGE, \
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

// Order in every hook: binding, (file_open: overlay internal open), arming,
// path, match. Unbound tasks leave after one hash lookup per cgroup level.
SEC("lsm/file_open")
int BPF_PROG(ig_file_open, struct file *file)
{
	struct file_eval e = {};
	struct mount *mnt;
	__u32 fmode, mask = 0;
	bool fi;

	if (!file_bound(&e))
		return 0;
	// overlayfs opens the backing file on a private clone mount
	// (clone_private_mount: mnt_ns = MNT_NS_INTERNAL = ERR_PTR(-EINVAL));
	// user space cannot create such a mount. Copy-up opens use it too.
	mnt = file_real_mount(BPF_CORE_READ(file, f_path.mnt));
	if ((long)BPF_CORE_READ(mnt, mnt_ns) == -EINVAL)
		return 0;
	if (!file_armed(&e))
		return 0;
	fmode = BPF_CORE_READ(file, f_mode);
	if (fmode & FILE_FMODE_READ)
		mask |= BIT(FILE_ACCESS_READ);
	if ((fmode & FILE_FMODE_WRITE) ||
	    (BPF_CORE_READ(file, f_flags) & FILE_O_TRUNC))
		mask |= BIT(FILE_ACCESS_WRITE);
	if (!mask)
		return 0;
	fi = file_from_image(BPF_CORE_READ(file, f_inode));
	FILE_JUDGE(&e, file_resolve_path(&file->f_path, e.x, &_start), mask, fi);
	return file_verdict(FILE_HOOK_FILE_OPEN, &e);
}

SEC("lsm/path_truncate")
int BPF_PROG(ig_file_truncate, const struct path *path)
{
	struct file_eval e = {};
	bool fi;

	if (!file_scope(&e))
		return 0;
	fi = file_dentry_from_image(BPF_CORE_READ(path, dentry));
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
		return 0;
	fi = file_dentry_from_image(BPF_CORE_READ(path, dentry));
	FILE_JUDGE(&e, file_resolve_path(path, e.x, &_start),
		   BIT(FILE_ACCESS_CHMOD), fi);
	return file_verdict(hook, &e);
}

SEC("lsm/path_chmod")
int BPF_PROG(ig_file_chmod, const struct path *path)
{
	return file_attr(FILE_HOOK_PATH_CHMOD, path);
}

SEC("lsm/path_chown")
int BPF_PROG(ig_file_chown, const struct path *path)
{
	return file_attr(FILE_HOOK_PATH_CHOWN, path);
}

// bpf_d_path is not allowed in path_mknod: the new name is resolved by the
// walk from its (negative) dentry, on the directory's mount.
SEC("lsm/path_mknod")
int BPF_PROG(ig_file_mknod, const struct path *dir, struct dentry *dentry)
{
	struct file_eval e = {};

	if (!file_scope(&e))
		return 0;
	FILE_JUDGE(&e,
		   file_resolve_walk(dentry, BPF_CORE_READ(dir, mnt), e.x,
				     &_start),
		   BIT(FILE_ACCESS_CREATE), false);
	return file_verdict(FILE_HOOK_PATH_MKNOD, &e);
}

static __always_inline int file_dir_entry(enum file_hook hook,
					  const struct path *dir,
					  struct dentry *dentry,
					  enum file_access access)
{
	struct file_eval e = {};
	bool fi = false;

	if (!file_scope(&e))
		return 0;
	if (access == FILE_ACCESS_DELETE)
		fi = file_dentry_from_image(dentry);
	FILE_JUDGE(&e, file_resolve_dir_name(dir, dentry, e.x, &_start),
		   BIT(access), fi);
	return file_verdict(hook, &e);
}

SEC("lsm/path_mkdir")
int BPF_PROG(ig_file_mkdir, const struct path *dir, struct dentry *dentry)
{
	return file_dir_entry(FILE_HOOK_PATH_MKDIR, dir, dentry,
			      FILE_ACCESS_CREATE);
}

SEC("lsm/path_symlink")
int BPF_PROG(ig_file_symlink, const struct path *dir, struct dentry *dentry)
{
	return file_dir_entry(FILE_HOOK_PATH_SYMLINK, dir, dentry,
			      FILE_ACCESS_CREATE);
}

SEC("lsm/path_unlink")
int BPF_PROG(ig_file_unlink, const struct path *dir, struct dentry *dentry)
{
	return file_dir_entry(FILE_HOOK_PATH_UNLINK, dir, dentry,
			      FILE_ACCESS_DELETE);
}

SEC("lsm/path_rmdir")
int BPF_PROG(ig_file_rmdir, const struct path *dir, struct dentry *dentry)
{
	return file_dir_entry(FILE_HOOK_PATH_RMDIR, dir, dentry,
			      FILE_ACCESS_DELETE);
}

// A hard link: the new name is a create; the old name is a move source. Both
// names are on new_dir's mount (the kernel refuses a link across mounts).
SEC("lsm/path_link")
int BPF_PROG(ig_file_link, struct dentry *old_dentry, const struct path *new_dir,
	     struct dentry *new_dentry)
{
	struct file_eval e = {};
	bool fi;

	if (!file_scope(&e))
		return 0;
	FILE_JUDGE(&e, file_resolve_dir_name(new_dir, new_dentry, e.x, &_start),
		   BIT(FILE_ACCESS_CREATE), false);
	fi = file_dentry_from_image(old_dentry);
	FILE_JUDGE(&e,
		   file_resolve_walk(old_dentry, BPF_CORE_READ(new_dir, mnt),
				     e.x, &_start),
		   BIT(FILE_ACCESS_RENAME) | BIT(FILE_ACCESS_MOVE_SOURCE), fi);
	return file_verdict(FILE_HOOK_PATH_LINK, &e);
}

SEC("lsm/path_rename")
int BPF_PROG(ig_file_rename, const struct path *old_dir,
	     struct dentry *old_dentry, const struct path *new_dir,
	     struct dentry *new_dentry, unsigned int flags)
{
	struct file_eval e = {};
	__u32 new_mask = BIT(FILE_ACCESS_RENAME);
	bool fi;

	if (!file_scope(&e))
		return 0;
	fi = file_dentry_from_image(old_dentry);
	FILE_JUDGE(&e, file_resolve_dir_name(old_dir, old_dentry, e.x, &_start),
		   BIT(FILE_ACCESS_RENAME) | BIT(FILE_ACCESS_MOVE_SOURCE), fi);
	fi = false;
	if (flags & FILE_RENAME_EXCHANGE) {
		new_mask |= BIT(FILE_ACCESS_MOVE_SOURCE);
		fi = file_dentry_from_image(new_dentry);
	} else if (BPF_CORE_READ(new_dentry, d_inode)) {
		new_mask |= BIT(FILE_ACCESS_WRITE) | BIT(FILE_ACCESS_DELETE);
		fi = file_dentry_from_image(new_dentry);
	} else {
		new_mask |= BIT(FILE_ACCESS_CREATE);
	}
	FILE_JUDGE(&e, file_resolve_dir_name(new_dir, new_dentry, e.x, &_start),
		   new_mask, fi);
	return file_verdict(FILE_HOOK_PATH_RENAME, &e);
}

/* Arming */

// file_enforcing_slot returns true, with the slot, when the current task is
// in a bound cgroup whose slot enforces.
static __always_inline bool file_enforcing_slot(__u32 *slot)
{
	const struct file_slot *s;
	__u64 cgid = 0;

	if (!binding_lookup(&cgid, slot))
		return false;
	s = file_slot_get(*slot);
	return s && s->mode == POLICY_MODE_ENFORCE;
}

// The exec hook cannot fail the exec. A lost mark in an enforcing slot is a
// tracking fault: the owner reports the binding as not confirmed.
SEC("lsm/bprm_committed_creds")
int BPF_PROG(ig_file_exec)
{
	__u32 slot = 0;

	if (!arming_on_exec()) {
		verdict_count(VERDICT_COUNT_SECTION_ERROR);
		if (file_enforcing_slot(&slot))
			arming_slot_fault(slot);
	}
	return 0;
}

// An armed parent whose child could not be marked: an unmarked child would
// escape every rule, so an enforcing slot refuses the fork and counts a
// tracking fault. An audit slot or an unbound cgroup allows it. A clone into
// another cgroup is refused too, because the child's binding is not known.
SEC("lsm/task_alloc")
int BPF_PROG(ig_file_task_alloc, struct task_struct *task,
	     unsigned long clone_flags)
{
	__u32 slot = 0;

	if (arming_on_fork(task, clone_flags))
		return 0;
	verdict_count(VERDICT_COUNT_SECTION_ERROR);
	if (file_enforcing_slot(&slot)) {
		arming_slot_fault(slot);
		return -ENOMEM;
	}
	if ((__u64)clone_flags & CLONE_INTO_CGROUP)
		return -ENOMEM;
	return 0;
}
