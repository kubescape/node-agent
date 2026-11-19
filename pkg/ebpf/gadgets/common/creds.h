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
// - the credentials a task of a binding prepares (its cred_prepare program);
// - the credentials an io_uring request of a task of a binding applies (its
//   uring_override_creds program: a personality registered before the bind);
// - at each bind and heal, the credentials (cred and real_cred) of every task
//   of the binding (CRED_WALK_PROGRAM, run by the owner for each task of the
//   cgroup.threads files). A credential prepared before the bind that no task
//   holds at the bind, and that no request applies through a personality, is
//   not recorded: the credentials of an SQPOLL ring set up with
//   IORING_SETUP_ATTACH_WQ before the bind, by credentials the task replaced
//   before the bind, and the credentials of a request in flight at the bind.
// cred_free deletes the entry.
//
// Each binding may hold cred_quota entries. Over its quota, or when the
// record is full, the section refuses the preparation for a Strict binding
// (and counts a slot fault) and lets it run for an Audit one. A task outside
// every binding records nothing. Key CRED_TOTAL of the counter map counts all
// entries; the owner reports the fill level.
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
#define CRED_RECORD_MAX 262144
#define CRED_QUOTA_DEFAULT 16384

// Keys of the counter map besides the binding cgroups.
#define CRED_TOTAL 0ULL
// The cgroup of the owner's probe entries (no quota).
#define CRED_PROBE (~0ULL)

enum cred_result {
	CRED_OK = 0,
	// The record or the counter map is full.
	CRED_FULL = 1,
	// The binding holds cred_quota entries.
	CRED_OVER_QUOTA = 2,
	// CRED_WALK_PROGRAM: the task exited or left the cgroup.
	CRED_GONE = 3,
};

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

// Entries per binding cgroup, plus CRED_TOTAL and CRED_PROBE. The owner
// deletes a binding's counter when it unbinds it.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BINDINGS_MAX + 2);
	__type(key, __u64);
	__type(value, __u64);
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

// Entries one binding may hold. The owner sets it (Config.CredQuota).
const volatile __u32 cred_quota = CRED_QUOTA_DEFAULT;

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

static __always_inline __u64 *cred_counter(__u64 key)
{
	__u64 *count = bpf_map_lookup_elem(&SANDBOX_MAP(cred_counts), &key);
	__u64 zero = 0;

	if (count)
		return count;
	bpf_map_update_elem(&SANDBOX_MAP(cred_counts), &key, &zero, BPF_NOEXIST);
	return bpf_map_lookup_elem(&SANDBOX_MAP(cred_counts), &key);
}

static __always_inline void cred_uncount(__u64 key)
{
	__u64 *count = bpf_map_lookup_elem(&SANDBOX_MAP(cred_counts), &key);

	// Never below 0: the owner may have reset the counter.
	if (count && *count)
		__sync_fetch_and_sub(count, 1);
}

// cred_record adds cred for the binding cgroup. A cred already in the record
// is not counted again.
static __always_inline int cred_record(const void *cred, __u64 cgroup)
{
	struct cred_entry entry = { .cgroup = cgroup };
	__u64 key = (__u64)cred;
	__u64 *count, *total;

	if (cred_record_fail)
		return CRED_FULL;
	if (bpf_map_lookup_elem(&SANDBOX_MAP(creds), &key))
		return CRED_OK;
	count = cred_counter(cgroup);
	total = cred_counter(CRED_TOTAL);
	if (!count || !total)
		return CRED_FULL;
	if (cgroup != CRED_PROBE && *count >= cred_quota)
		return CRED_OVER_QUOTA;
	if (bpf_map_update_elem(&SANDBOX_MAP(creds), &key, &entry, BPF_NOEXIST))
		// Recorded meanwhile on another CPU, or the record is full.
		return cred_recorded(cred) ? CRED_OK : CRED_FULL;
	__sync_fetch_and_add(count, 1);
	__sync_fetch_and_add(total, 1);
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
		return cred_record(cred, CRED_PROBE);
	if (!binding_lookup(cgid, slot, flags))
		return CRED_OK;
	*bound = true;
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
	cred_uncount(CRED_TOTAL);
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
	const struct cred *cred, *real;
	int ret = CRED_GONE;

	if (!task)
		return CRED_GONE;
	// In an RCU read section, so the credentials cannot be freed (an RCU
	// callback) before they are recorded.
	bpf_rcu_read_lock();
	if (BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, id) == args->task_cgroup) {
		cred = BPF_CORE_READ(task, cred);
		real = BPF_CORE_READ(task, real_cred);
		ret = cred_record(cred, args->cgroup);
		if (ret == CRED_OK && real != cred)
			ret = cred_record(real, args->cgroup);
	}
	bpf_rcu_read_unlock();
	bpf_task_release(task);
	if (ret == CRED_FULL || ret == CRED_OVER_QUOTA) {
		if (args->flags & BINDING_STRICT)
			arming_slot_fault(args->slot);
		else
			arming_slot_unevaluated(args->slot);
	}
	return ret;
}

// CRED_WALK_PROGRAM defines the section's walk program. The owner runs it
// (BPF_PROG_TEST_RUN) with a struct cred_walk_args; it returns an enum
// cred_result.
#define CRED_WALK_PROGRAM(name)                          \
	SEC("syscall")                                   \
	int name(struct cred_walk_args *args)            \
	{                                                \
		return cred_walk(args);                  \
	}

#endif /* __ENFORCEMENT_CREDS_H */
