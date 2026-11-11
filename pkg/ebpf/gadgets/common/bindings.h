// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Kubescape Authors

// Container binding map of a node-wide enforcement gadget instance:
//   key:   cgroup v2 id
//   value: the policy slot of the container (one combination of policies) and
//          the binding flags
// Named <section>bindings (pin.h), version 1 (gadget annotation
// sandbox-bindings-version), so it never collides with the enforce_exec
// `bindings` map of the Inspektor Gadget fork, which has the same key and
// value size but another value meaning, when both are in one collection.
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

#include "pin.h"

#define BINDINGS_MAX 1024

// Number of cgroup levels checked for a BINDING_SUBTREE parent. 1 (the
// enforce_exec behaviour) checks the task's own cgroup only. A subtree binding
// covers its descendants at any depth when its own level is below this value;
// the owner refuses a subtree binding at a deeper level.
#ifndef BINDINGS_CGROUP_DEPTH
#define BINDINGS_CGROUP_DEPTH 1
#endif

// sandbox_binding.flags
#define BINDING_SUBTREE (1U << 0) // also covers the descendant cgroups
#define BINDING_STRICT (1U << 1) // the slot enforces: a fault denies
// Owner-admitted runtime helper exemption (see arming_on_exec in arming.h).
#define BINDING_RUNTIME_HELPERS (1U << 2)
// Set by binding_lookup only, never stored: the task is in a descendant cgroup
// of a Strict exact binding. The binding does not cover it, but a Strict
// workload that moved itself into a child cgroup must not run unjudged, so the
// caller treats it as a structural fault (deny).
#define BINDING_OUTSIDE_SCOPE (1U << 31)

struct sandbox_binding {
	__u32 slot;
	__u32 flags;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BINDINGS_MAX);
	__type(key, __u64);
	__type(value, struct sandbox_binding);
	SANDBOX_PINNED;
} SANDBOX_MAP(bindings) SEC(".maps");

// binding_lookup returns true when a binding covers the current task: the
// binding of the task's own cgroup, or else the nearest bound parent when it
// has BINDING_SUBTREE. When the nearest bound parent is a Strict exact
// binding, it is returned with BINDING_OUTSIDE_SCOPE added; an Audit exact
// one covers nothing (Audit never blocks).
static __always_inline bool binding_lookup(__u64 *cgroup, __u32 *slot,
					   __u32 *flags)
{
	__u64 id = bpf_get_current_cgroup_id();
	struct sandbox_binding *value =
		bpf_map_lookup_elem(&SANDBOX_MAP(bindings), &id);

#if BINDINGS_CGROUP_DEPTH > 1
	if (!value) {
		struct task_struct *task = bpf_get_current_task_btf();
#ifdef BINDINGS_DIRECT_LEVEL
		// Opt-in for programs whose bpf_get_current_task_btf() pointer can
		// be read directly (BPF LSM, tracing): plain loads instead of three
		// bpf_probe_read_kernel calls.
		int level = task->cgroups->dfl_cgrp->level;
#else
		int level = BPF_CORE_READ(task, cgroups, dfl_cgrp, level);
#endif
		struct sandbox_binding *parent;
		__u64 parent_id;

		// From the top down, so a subtree binding covers a task at any
		// depth below it. The last match is the nearest bound parent. A
		// binding deeper than level BINDINGS_CGROUP_DEPTH - 1 is not seen
		// from its descendants.
		for (int i = 1; i < BINDINGS_CGROUP_DEPTH; i++) {
			if (i >= level)
				break;
			parent_id = bpf_get_current_ancestor_cgroup_id(i);
			parent = bpf_map_lookup_elem(&SANDBOX_MAP(bindings), &parent_id);
			if (parent) {
				value = parent;
				id = parent_id;
			}
		}
	}
#endif
	if (!value)
		return false;
	if (id != bpf_get_current_cgroup_id() && !(value->flags & BINDING_SUBTREE)) {
		// The nearest bound parent is exact: an Audit one does not cover
		// the task; a Strict one marks it outside its scope.
		if (!(value->flags & BINDING_STRICT))
			return false;
		*cgroup = id;
		*slot = value->slot;
		*flags = value->flags | BINDING_OUTSIDE_SCOPE;
		return true;
	}
	*cgroup = id;
	*slot = value->slot;
	*flags = value->flags;
	return true;
}

#endif /* __ENFORCEMENT_BINDINGS_H */
