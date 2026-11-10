// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Kubescape Authors

// Container binding map of a node-wide enforcement gadget instance:
//   key:   cgroup v2 id
//   value: the policy slot of the container (one combination of policies) and
//          the binding flags
// Same name, key and value size as the enforce_exec `bindings` map of the
// Inspektor Gadget fork. The value meaning differs: there it is 0 or a runtime
// mount namespace inode (restricted binding).
//
// Scope is exact by default, as in enforce_exec: a binding covers the tasks of
// its own cgroup only. BINDING_SUBTREE extends one binding to the descendant
// cgroups. The owner sets it only for a parent cgroup bound before its containers
// start, and reports it in status.

#ifndef __ENFORCEMENT_BINDINGS_H
#define __ENFORCEMENT_BINDINGS_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define BINDINGS_MAX 1024

// Number of cgroup levels checked for a BINDING_SUBTREE parent. 1 (the
// enforce_exec behaviour) checks the task's own cgroup only. A subtree binding
// covers its descendants at any depth when its own level is below this value;
// the owner refuses a subtree binding at a deeper level.
#ifndef BINDINGS_CGROUP_DEPTH
#define BINDINGS_CGROUP_DEPTH 1
#endif

// binding_value.flags
#define BINDING_SUBTREE (1U << 0) // also covers the descendant cgroups
#define BINDING_STRICT (1U << 1) // the slot enforces: a fault denies
// Owner-admitted runtime helper exemption (see arming_on_exec in arming.h).
#define BINDING_RUNTIME_HELPERS (1U << 2)

struct binding_value {
	__u32 slot;
	__u32 flags;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BINDINGS_MAX);
	__type(key, __u64);
	__type(value, struct binding_value);
} bindings SEC(".maps");

// binding_lookup returns true when a binding covers the current task: the
// binding of the task's own cgroup, or else the nearest parent binding with
// BINDING_SUBTREE. It returns the bound cgroup id, the slot and the flags.
static __always_inline bool binding_lookup(__u64 *cgroup, __u32 *slot,
					   __u32 *flags)
{
	__u64 id = bpf_get_current_cgroup_id();
	struct binding_value *value = bpf_map_lookup_elem(&bindings, &id);

#if BINDINGS_CGROUP_DEPTH > 1
	if (!value) {
		struct task_struct *task = bpf_get_current_task_btf();
		int level = BPF_CORE_READ(task, cgroups, dfl_cgrp, level);
		struct binding_value *parent;
		__u64 parent_id;

		// From the top down, so a subtree binding covers a task at any
		// depth below it. The last match is the nearest parent.
		for (int i = 1; i < BINDINGS_CGROUP_DEPTH; i++) {
			if (i >= level)
				break;
			parent_id = bpf_get_current_ancestor_cgroup_id(i);
			parent = bpf_map_lookup_elem(&bindings, &parent_id);
			if (parent && (parent->flags & BINDING_SUBTREE)) {
				value = parent;
				id = parent_id;
			}
		}
	}
#endif
	if (!value)
		return false;
	*cgroup = id;
	*slot = value->slot;
	*flags = value->flags;
	return true;
}

#endif /* __ENFORCEMENT_BINDINGS_H */
