// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Kubescape Authors

// Kernel test of the task_alloc composition of ../../../root_barrier.h with a
// gadget that owns task_alloc and allocates per-task state there (as
// enforce_exec does). With OWNER_INLINE the gadget defines
// ROOT_BARRIER_NO_TASK_ALLOC_PROGRAM and calls the barrier first, inside its
// own program; without it, rb_task_alloc is a separate program on the hook.

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define OWNER_CLONE_NEWNS 0x00020000ULL

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u64);
	__type(value, __u32);
} covered_cgroups SEC(".maps");

// Per-task state of the owner, keyed by the task address.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u32);
} owner_tasks SEC(".maps");

// Allocations for a clone with CLONE_NEWNS.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} owner_newns_allocs SEC(".maps");

static __always_inline bool covered(struct task_struct *task)
{
	__u64 cgroup = bpf_get_current_cgroup_id();

	return bpf_map_lookup_elem(&covered_cgroups, &cgroup) != NULL;
}

#ifdef OWNER_INLINE
#define ROOT_BARRIER_NO_TASK_ALLOC_PROGRAM
#endif
#define ROOT_BARRIER_COVERED(task) covered(task)
#include "../../../root_barrier.h"

SEC("lsm/task_alloc")
long BPF_PROG(own_task_alloc, struct task_struct *child,
	      unsigned long clone_flags, int ret)
{
	__s64 prior = ROOT_BARRIER_PRIOR(2);
	__u64 key = (__u64)child;
	__u32 zero = 0, one = 1;
	__u64 *allocs;

	if (prior)
		return prior;
#ifdef OWNER_INLINE
	ret = root_barrier_task_alloc(ctx, clone_flags);
	if (ret)
		return ret;
#endif
	if (!covered(bpf_get_current_task_btf()))
		return 0;
	bpf_map_update_elem(&owner_tasks, &key, &one, BPF_ANY);
	allocs = bpf_map_lookup_elem(&owner_newns_allocs, &zero);
	if (allocs && (clone_flags & OWNER_CLONE_NEWNS))
		__sync_fetch_and_add(allocs, 1);
	return 0;
}

SEC("lsm/task_free")
int BPF_PROG(own_task_free, struct task_struct *task)
{
	__u64 key = (__u64)task;

	bpf_map_delete_elem(&owner_tasks, &key);
	return 0;
}
