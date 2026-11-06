// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Kubescape Authors

// root_barrier: the shared root barrier (../common/root_barrier.h) alone, for
// a set of cgroups. It shows how an enforcer includes the barrier, and lets the
// barrier be tested with Inspektor Gadget alone.
//
// Coverage has the shape of the enforce_exec `bindings` map: a task is covered
// when its cgroup or any ancestor is in covered_cgroups, unless the value is a mount namespace inode and the
// task runs in that namespace (the container runtime's own setup work in the
// cgroup, for a restricted binding). The ancestor match keeps a task covered
// when it moves into a child cgroup it creates, or when clone3 starts its child
// in one (CLONE_INTO_CGROUP). The walk starts at the top of the hierarchy, so
// a task at any depth below a covered cgroup matches, as long as the covered
// cgroup itself is at most COVERED_CGROUPS_LEVELS levels below the root.

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/macros.h>

char LICENSE[] SEC("license") = "GPL";

#define COVERED_CGROUPS_MAX 1024

// cgroup v2 id -> 0, or the mount namespace inode that is not covered.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, COVERED_CGROUPS_MAX);
	__type(key, __u64);
	__type(value, __u64);
} covered_cgroups SEC(".maps");

#define COVERED_CGROUPS_LEVELS 16

static __always_inline bool covered(struct task_struct *task)
{
	int level = BPF_CORE_READ(task, cgroups, dfl_cgrp, level);
	__u64 *exempt = NULL;

	// Level 0 is the root cgroup, which is never covered.
	for (int i = 1; i <= COVERED_CGROUPS_LEVELS && !exempt; i++) {
		__u64 cgroup;

		if (i > level)
			break;
		cgroup = bpf_get_current_ancestor_cgroup_id(i);
		exempt = bpf_map_lookup_elem(&covered_cgroups, &cgroup);
	}
	if (!exempt)
		return false;
	if (*exempt && BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum) == *exempt)
		return false;
	return true;
}

struct event {
	__u64 cgroup;
	__u32 host_pid;
	__u32 host_tid;
	char comm[16];
	// enum root_barrier_op
	__u32 op_raw;
	// Clone flags or capability of the denied call.
	__u64 arg;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} events SEC(".maps");
GADGET_TRACER(denial, events, event);

static __always_inline void report(__u32 op, __u64 arg)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	if (!e)
		return;
	e->cgroup = bpf_get_current_cgroup_id();
	e->host_pid = pid_tgid >> 32;
	e->host_tid = (__u32)pid_tgid;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	e->op_raw = op;
	e->arg = arg;
	bpf_ringbuf_submit(e, 0);
}

#define ROOT_BARRIER_COVERED(task) covered(task)
#define ROOT_BARRIER_ON_DENY(ctx, op, arg) report(op, arg)
#include "../common/root_barrier.h"
