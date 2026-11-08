// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Kubescape Authors

// root_barrier: the shared root barrier (../common/root_barrier.h) alone, for
// a set of cgroups. It shows how an enforcer includes the barrier, and lets the
// barrier be tested with Inspektor Gadget alone.
//
// Coverage has the shape of the enforce_exec `bindings` map, plus two flags
// per binding:
//
// - ENFORCE: the binding can enforce. Only such a binding is covered. An
//   audit-only binding is never covered, so the barrier never blocks it.
// - EXACT: only tasks in the bound cgroup itself are covered (the strict
//   binding scope of enforce_exec). Without it, a task in a descendant cgroup
//   is covered too: it may have moved into a child cgroup it created, or
//   clone3 may have started it in one (CLONE_INTO_CGROUP).
//
// A task in the bound cgroup's runtime mount namespace (the value's exempt
// inode, for a restricted binding) is not covered: that is the container
// runtime's own setup work in the cgroup.
//
// The descendant match walks from the top of the hierarchy, so a task at any
// depth below a bound cgroup matches, as long as the bound cgroup itself is at
// most COVERED_CGROUPS_LEVELS levels below the root. An exact binding matches
// at any depth.

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/macros.h>

char LICENSE[] SEC("license") = "GPL";

#define COVERED_CGROUPS_MAX 1024

#define COVERED_ENFORCE 0x1
#define COVERED_EXACT 0x2

struct covered_cgroup {
	// Mount namespace inode that is not covered; 0 = none.
	__u64 exempt_mntns;
	__u32 flags;
	__u32 reserved;
};

// cgroup v2 id -> binding.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, COVERED_CGROUPS_MAX);
	__type(key, __u64);
	__type(value, struct covered_cgroup);
} covered_cgroups SEC(".maps");

#define COVERED_CGROUPS_LEVELS 16

static __always_inline bool covered_by(const struct covered_cgroup *c,
				       struct task_struct *task, bool own)
{
	if (!c || !(c->flags & COVERED_ENFORCE))
		return false;
	if ((c->flags & COVERED_EXACT) && !own)
		return false;
	if (c->exempt_mntns &&
	    BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum) == c->exempt_mntns)
		return false;
	return true;
}

static __always_inline bool covered(struct task_struct *task)
{
	int level = BPF_CORE_READ(task, cgroups, dfl_cgrp, level);
	__u64 own = bpf_get_current_cgroup_id();

	if (covered_by(bpf_map_lookup_elem(&covered_cgroups, &own), task, true))
		return true;
	// Ancestors. Level 0 is the root cgroup, which is never covered.
	for (int i = 1; i <= COVERED_CGROUPS_LEVELS && i < level; i++) {
		__u64 cgroup = bpf_get_current_ancestor_cgroup_id(i);

		if (covered_by(bpf_map_lookup_elem(&covered_cgroups, &cgroup),
			       task, false))
			return true;
	}
	return false;
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
