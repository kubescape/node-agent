// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Kubescape Authors

// Container binding map of a node-wide enforcement gadget instance:
//   key:   cgroup v2 id
//   value: the policy slot of the container (one combination of policies)
// Same name, key and value size as the enforce_exec `bindings` map of the
// Inspektor Gadget fork. The value meaning differs: there it is 0 or a runtime
// mount namespace inode (restricted binding).

#ifndef __ENFORCEMENT_BINDINGS_H
#define __ENFORCEMENT_BINDINGS_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define BINDINGS_MAX 1024

// Number of cgroup levels checked: the task's cgroup and its parents. 1 (the
// enforce_exec behaviour) checks the task's own cgroup only.
#ifndef BINDINGS_CGROUP_DEPTH
#define BINDINGS_CGROUP_DEPTH 1
#endif

struct binding_value {
	__u32 slot;
	__u32 reserved;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BINDINGS_MAX);
	__type(key, __u64);
	__type(value, struct binding_value);
} bindings SEC(".maps");

// binding_lookup returns true when the current task's cgroup (or a parent up
// to BINDINGS_CGROUP_DEPTH) is bound, with the bound cgroup id and its slot.
static __always_inline bool binding_lookup(__u64 *cgroup, __u32 *slot)
{
	struct task_struct *task = bpf_get_current_task_btf();
	__u64 id = bpf_get_current_cgroup_id();
	struct binding_value *value = bpf_map_lookup_elem(&bindings, &id);

#if BINDINGS_CGROUP_DEPTH > 1
	int level = BPF_CORE_READ(task, cgroups, dfl_cgrp, level);

	for (int i = 1; i < BINDINGS_CGROUP_DEPTH && !value; i++) {
		if (level - i < 1)
			break;
		id = bpf_get_current_ancestor_cgroup_id(level - i);
		value = bpf_map_lookup_elem(&bindings, &id);
	}
#endif
	if (!value)
		return false;
	*cgroup = id;
	*slot = value->slot;
	return true;
}

#endif /* __ENFORCEMENT_BINDINGS_H */
