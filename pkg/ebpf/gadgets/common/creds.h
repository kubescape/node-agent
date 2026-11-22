// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Kubescape Authors

// The record of the workload's credentials, by address. A hook that meets
// overridden credentials (cred != real_cred) judges them when they are in the
// record: the workload holds them, so they are its own (for example an
// io_uring request after a capset or under a personality, in an io-wq or
// SQPOLL worker or from task_work, or access() with its override). Overlayfs
// copy-up overrides to the mounter's credentials, which the container runtime
// prepared: they are not in the record.
//
// A section records:
// - the credentials a task of a binding prepares from its own credentials
//   or from recorded ones (its cred_prepare program, cred_prepared_from_ours),
//   and the blank credentials of KEYCTL_SESSION_TO_PARENT (its
//   cred_alloc_blank program: they become the parent's credentials without
//   cred_prepare). A copy of overridden credentials that are not in the
//   record is not the workload's: overlayfs prepares copies of the mounter's
//   credentials for its copy-up (in the SELinux copy-up hook) and its create,
//   in the container's task. Recorded, they would be judged, and a denied
//   DAC capability would fail a copy-up (with SELinux) and a create over a
//   whiteout (any LSM): EACCES;
// - the credentials an io_uring request of a task of a binding applies (its
//   uring_override_creds program: a personality registered before the bind);
// - at each bind and heal, the credentials (real_cred) of every task
//   of the binding (CRED_WALK_PROGRAM, run by the owner for each task of the
//   cgroup.threads files). The walk also reports a task that holds io_uring
//   rings (its io_uring context lists one until the ring is released), an
//   SQPOLL thread (it lives as long as its rings), and an exiting task whose
//   io-wq still runs (its exit empties the context first, then runs the
//   queued bound work): the owner refuses a new Strict binding then
//   (enforcement.ErrIoUringHeld), because a request queued before the bind,
//   or an SQPOLL ring attached before it, can run later under credentials
//   that no task holds and the walk cannot see. An io-wq worker alone is not
//   a ring: io-wq is per task, and on 6.12 its last worker lives until the
//   task exits, after the rings are closed.
// cred_free deletes the entry.
//
// Each binding may hold cred_quota entries. Past cred_pressure entries in
// the whole record (75% by default), a binding may hold only
// (record size - cred_pressure) / active bindings: the bindings under that
// share together fit in the last 25%, so bindings that fill their quotas
// cannot take every entry (a reserve). Over its quota or that share, or when
// the record is full, the section refuses the preparation for a Strict
// binding (and counts a slot fault) and lets it run for an Audit one. A task
// outside every binding records nothing. A per-CPU total keeps the record's
// fill without an atomic shared by every CPU; it is read only for a binding
// that holds more than the smallest share (CRED_SHARE_FLOOR). A freed
// credential leaves the record after an RCU grace period, so a burst counts
// until then: 16000 fork+exec in one second on 8 CPUs held about 6000
// entries; a loop of 40000 capset calls held almost all of them until it
// ended (both gone 100 to 400 ms later).
//
// Freed credentials leave the record only when an LSM with a cred blob is
// active (security_cred_free returns early otherwise). The owner checks at
// start that a freed credential is deleted (enforcement.Bindings probe) and
// refuses to start otherwise. The maps are pinned, so a replacement instance
// keeps the record; the owner purges it when no other instance's cred_free
// runs. A delete that fails leaves a stale address: credentials allocated
// there later are judged, never skipped.
//
// Include it after bindings.h and arming.h.

#ifndef __ENFORCEMENT_CREDS_H
#define __ENFORCEMENT_CREDS_H

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "pin.h"

// The record is allocated on use (BPF_F_NO_PREALLOC). The loader sizes maps
// before the owner sets its constants, and a pinned map keeps its size, so
// the size is fixed; the quota per binding is a constant.
#define CRED_RECORD_MAX 524288
#define CRED_QUOTA_DEFAULT 32768
#define CRED_PRESSURE_DEFAULT (CRED_RECORD_MAX / 4 * 3)
// A binding under this count is never over its share past the pressure level
// (the share of the largest number of bindings), so it skips the total.
#define CRED_SHARE_FLOOR ((CRED_RECORD_MAX - CRED_PRESSURE_DEFAULT) / BINDINGS_MAX)
// The total sums at most this many CPUs.
#define CRED_MAX_CPUS 512

// The owner's probe entries: CRED_PROBE | the probe's thread ID is their
// counter key (no quota). A cgroup ID never has this bit.
#define CRED_PROBE (1ULL << 63)

enum cred_result {
	CRED_OK = 0,
	// The record or the counter map is full.
	CRED_FULL = 1,
	// The binding holds cred_quota entries.
	CRED_OVER_QUOTA = 2,
	// CRED_WALK_PROGRAM: the task exited or left the cgroup.
	CRED_GONE = 3,
};

// CRED_WALK_PROGRAM adds this bit to its result when the task holds io_uring
// rings.
#define CRED_IO_URING 0x100
// PF_IO_WORKER and PF_EXITING (include/linux/sched.h, the same on 6.12 and
// 6.18). An io thread is an io-wq worker or an SQPOLL thread.
#define CRED_PF_IO_WORKER 0x00000010
#define CRED_PF_EXITING 0x00000004

struct cred_entry {
	// The binding cgroup that holds the entry.
	__u64 cgroup;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CRED_RECORD_MAX);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u64);
	__type(value, struct cred_entry);
	SANDBOX_PINNED;
} SANDBOX_MAP(creds) SEC(".maps");

// Entries per binding cgroup, plus one counter per running probe. The owner
// deletes a binding's counter once it is unbound and its entries are freed
// (so a rebind keeps counting them), and a probe's when the probe ends. There is no node-wide counter: a shared atomic
// costs every fork on the node.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2 * BINDINGS_MAX + 16);
	__type(key, __u64);
	__type(value, __s64);
	SANDBOX_PINNED;
} SANDBOX_MAP(cred_counts) SEC(".maps");

// cred_instance is a map of the instance alone (not pinned). It holds the
// thread ID of the owner's probe (0 when no probe runs). cred_free uses it, so
// its program uses a map that no other instance has: a program whose maps are
// all pinned would look like a program of every instance to the link walk of
// the restart pins (enforcement.PinInstance).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} cred_instance SEC(".maps");

// Entries one binding may hold, the record's fill from which a binding may
// hold only its share, and the size the share is computed from. The owner
// sets them (Config.CredQuota; pressure and size only in tests, which cannot
// fill the real record). cred_cpus is the number of possible CPUs.
const volatile __u32 cred_quota = CRED_QUOTA_DEFAULT;
const volatile __u32 cred_pressure = CRED_PRESSURE_DEFAULT;
const volatile __u32 cred_size = CRED_RECORD_MAX;
const volatile __u32 cred_cpus = 1;

// The entries of the record, counted per CPU (a CPU's count can be negative:
// an entry can be freed on another CPU than the one that added it).
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __s64);
	SANDBOX_PINNED;
} SANDBOX_MAP(cred_total) SEC(".maps");

// The number of bindings, written by the owner at each bind and unbind (0
// reads as 1): the entries of the pinned binding map, so two instances that
// share the record during a replacement write the same count.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
	SANDBOX_PINNED;
} SANDBOX_MAP(cred_active) SEC(".maps");

static __always_inline void cred_total_add(__s64 delta)
{
	__u32 zero = 0;
	__s64 *v = bpf_map_lookup_elem(&SANDBOX_MAP(cred_total), &zero);

	if (v)
		__sync_fetch_and_add(v, delta);
}

static __always_inline __s64 cred_total_sum(void)
{
	__u32 zero = 0;
	__s64 sum = 0, *v;

	for (__u32 cpu = 0; cpu < CRED_MAX_CPUS && cpu < cred_cpus; cpu++) {
		v = bpf_map_lookup_percpu_elem(&SANDBOX_MAP(cred_total), &zero, cpu);
		if (v)
			sum += *v;
	}
	return sum;
}

// cred_over_share reports whether a binding that holds count entries may not
// add one: the record is past cred_pressure and the binding holds its share
// of the rest ((cred_size - cred_pressure) / active bindings).
static __always_inline bool cred_over_share(__s64 count)
{
	__u32 zero = 0, active = 1, *a;

	if (count < CRED_SHARE_FLOOR && cred_pressure >= CRED_PRESSURE_DEFAULT &&
	    cred_size >= CRED_RECORD_MAX)
		return false;
	if (cred_total_sum() < (__s64)cred_pressure)
		return false;
	a = bpf_map_lookup_elem(&SANDBOX_MAP(cred_active), &zero);
	if (a && *a > 1)
		active = *a;
	return count >= (__s64)((cred_size - cred_pressure) / active);
}

// Fault injection for tests only: every record fails, as with a full record
// (cred_record_fail), or cred_free deletes nothing, as without an LSM with a
// cred blob (cred_forget_fail). The owner forces them to 0 outside kernel
// tests (enforcement.ForceTestSwitchesOff).
const volatile __u32 cred_record_fail = 0;
const volatile __u32 cred_forget_fail = 0;

// cred_recorded reports whether cred is in the record.
static __always_inline bool cred_recorded(const void *cred)
{
	__u64 key = (__u64)cred;

	return bpf_map_lookup_elem(&SANDBOX_MAP(creds), &key) != NULL;
}

// cred_prepared_from_ours reports whether credentials prepared from old (the
// task's current credentials, which prepare_creds copies) can be the
// workload's: old is the task's own (real_cred) or in the record. A copy made
// under another override has that override's capabilities (the mounter's,
// for overlayfs), not the workload's, and is used for that kernel operation
// only: a task commits credentials only while it runs on its own
// (commit_creds requires cred == real_cred). A child that fork gives a copy
// runs on it as its own credentials (real_cred), which are judged whether
// recorded or not.
static __always_inline bool cred_prepared_from_ours(const struct cred *old)
{
	struct task_struct *task = bpf_get_current_task_btf();

	return (void *)old == (void *)task->real_cred || cred_recorded(old);
}

static __always_inline __s64 *cred_counter(__u64 key)
{
	__s64 *count = bpf_map_lookup_elem(&SANDBOX_MAP(cred_counts), &key);
	__s64 zero = 0;

	if (count)
		return count;
	bpf_map_update_elem(&SANDBOX_MAP(cred_counts), &key, &zero, BPF_NOEXIST);
	return bpf_map_lookup_elem(&SANDBOX_MAP(cred_counts), &key);
}

static __always_inline void cred_uncount(__u64 key)
{
	__s64 *count = bpf_map_lookup_elem(&SANDBOX_MAP(cred_counts), &key);

	// Signed, always subtracted: a counter the owner recreated can go below
	// 0; readers clamp it at 0.
	if (count)
		__sync_fetch_and_add(count, -1);
}

// cred_record adds cred for the binding cgroup. A cred already in the record
// is not counted again.
static __always_inline int cred_record(const void *cred, __u64 cgroup)
{
	struct cred_entry entry = { .cgroup = cgroup };
	__u64 key = (__u64)cred;
	__s64 *count, held;

	if (bpf_map_lookup_elem(&SANDBOX_MAP(creds), &key))
		return CRED_OK;
	count = cred_counter(cgroup);
	if (!count)
		return CRED_FULL;
	held = *count < 0 ? 0 : *count;
	if (!(cgroup & CRED_PROBE) &&
	    (held >= (__s64)cred_quota || cred_over_share(held)))
		return CRED_OVER_QUOTA;
	if (bpf_map_update_elem(&SANDBOX_MAP(creds), &key, &entry, BPF_NOEXIST))
		// Recorded meanwhile on another CPU, or the record is full.
		return cred_recorded(cred) ? CRED_OK : CRED_FULL;
	__sync_fetch_and_add(count, 1);
	cred_total_add(1);
	return CRED_OK;
}

// cred_record_current records cred for the current task: under its binding
// (bound is set, with the binding's cgroup, slot and flags), or as a probe
// entry when the task is the owner's probe thread. CRED_OK when nothing needs
// recording.
static __always_inline int cred_record_current(const void *cred, __u64 *cgid,
					       __u32 *slot, __u32 *flags,
					       bool *bound)
{
	__u32 zero = 0, *probe = bpf_map_lookup_elem(&cred_instance, &zero);

	*bound = false;
	if (probe && *probe && *probe == (__u32)bpf_get_current_pid_tgid())
		return cred_record(cred, CRED_PROBE | *probe);
	if (!binding_lookup(cgid, slot, flags))
		return CRED_OK;
	*bound = true;
	if (cred_record_fail)
		return CRED_FULL;
	return cred_record(cred, *cgid);
}

// cred_forget deletes cred, from cred_free. During a reload both instances'
// cred_free run; only the one whose delete succeeds updates the counters.
static __always_inline void cred_forget(const void *cred)
{
	__u64 key = (__u64)cred, cgroup;
	struct cred_entry *entry;
	__u32 zero = 0;

	if (!bpf_map_lookup_elem(&cred_instance, &zero) || cred_forget_fail)
		return;
	entry = bpf_map_lookup_elem(&SANDBOX_MAP(creds), &key);
	if (!entry)
		return;
	cgroup = entry->cgroup;
	if (bpf_map_delete_elem(&SANDBOX_MAP(creds), &key))
		return;
	cred_uncount(cgroup);
	cred_total_add(-1);
}

extern struct task_struct *bpf_task_from_pid(s32 pid) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

// The context of CRED_WALK_PROGRAM (enforcement.credWalkArgs).
struct cred_walk_args {
	// A task ID in the initial PID namespace (cgroup.threads).
	__u32 tid;
	// The binding's flags (BINDING_STRICT) and slot, for a failed record.
	__u32 flags;
	__u32 slot;
	__u32 pad;
	// The binding cgroup, and the cgroup whose cgroup.threads listed tid.
	__u64 cgroup;
	__u64 task_cgroup;
};

// cred_walk records the credentials of one task of a binding. A record that
// fails counts a slot fault for a Strict binding and an unevaluated judgement
// for an Audit one.
static __always_inline int cred_walk(struct cred_walk_args *args)
{
	struct task_struct *task = bpf_task_from_pid(args->tid);
	const struct cred *real;
	int ret = CRED_GONE, ring = 0;
	unsigned int flags;

	if (!task)
		return CRED_GONE;
	if (cred_record_fail) {
		bpf_task_release(task);
		ret = CRED_FULL;
		goto fail;
	}
	// In an RCU read section, so the credentials cannot be freed (an RCU
	// callback) before they are recorded. Only real_cred: a different
	// subjective cred is an override in progress (overlayfs copy-up with the
	// runtime's credentials, or access() with credentials freed without RCU),
	// and recording it would judge the runtime or leave a freed address.
	bpf_rcu_read_lock();
	if (BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, id) == args->task_cgroup) {
		real = BPF_CORE_READ(task, real_cred);
		ret = cred_record(real, args->cgroup);
		// The task's io_uring context lists each ring it uses (also one
		// kept only through a registered ring fd). An SQPOLL thread is a
		// ring too (its creator may have exited): an io thread without
		// worker_private, which io-wq sets for its workers (the kernel's
		// io_wq_current_is_worker, 6.12 and 6.18). An io-wq worker has none
		// while it is created and while it exits, so it counts then, which
		// refuses (safe). An exiting task counts while its io-wq exists:
		// its exit empties the context, then its workers run the queued
		// bound work under the submitter's credentials.
		flags = BPF_CORE_READ(task, flags);
		if (BPF_CORE_READ(task, io_uring, xa.xa_head) ||
		    ((flags & CRED_PF_IO_WORKER) && !BPF_CORE_READ(task, worker_private)) ||
		    ((flags & CRED_PF_EXITING) && BPF_CORE_READ(task, io_uring, io_wq)))
			ring = CRED_IO_URING;
	}
	bpf_rcu_read_unlock();
	bpf_task_release(task);
fail:
	if (ret == CRED_FULL || ret == CRED_OVER_QUOTA) {
		if (args->flags & BINDING_STRICT)
			arming_slot_fault(args->slot);
		else
			arming_slot_unevaluated(args->slot);
	}
	return ret | ring;
}

// CRED_WALK_PROGRAM defines the section's walk program. The owner runs it
// (BPF_PROG_TEST_RUN) with a struct cred_walk_args; it returns an enum
// cred_result, with CRED_IO_URING when the task holds io_uring rings.
#define CRED_WALK_PROGRAM(name)                          \
	SEC("syscall")                                   \
	int name(struct cred_walk_args *args)            \
	{                                                \
		return cred_walk(args);                  \
	}

#endif /* __ENFORCEMENT_CREDS_H */
