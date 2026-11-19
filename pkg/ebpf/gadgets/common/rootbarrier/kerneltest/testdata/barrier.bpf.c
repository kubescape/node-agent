// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Kubescape Authors

// Kernel test of ../../../root_barrier.h: the coverage of a task is the value
// of its own cgroup in covered_cgroups (an exact binding), else not covered.

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u64);
	__type(value, __u32);
} covered_cgroups SEC(".maps");

static __always_inline __u32 coverage(struct task_struct *task)
{
	__u64 cgroup = bpf_get_current_cgroup_id();
	__u32 *value = bpf_map_lookup_elem(&covered_cgroups, &cgroup);

	return value ? *value : 0;
}

#define ROOT_BARRIER_COVERED(task) coverage(task)
#include "../../../root_barrier.h"
