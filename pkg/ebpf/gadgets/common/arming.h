// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Kubescape Authors

// Arming rule shared by the BPF LSM enforcement gadgets.
//
// A cgroup-scoped enforcer also sees the container runtime's own setup inside
// the container cgroup (runc init creates namespaces, mounts, pivots root and,
// for exec, joins namespaces). Seccomp never sees that work because runc
// applies the filter as its last step, right before it execs the workload.
//
// This header gives the same boundary to BPF: a task is "armed" when it
// executes a program outside the host mount namespace, and a child inherits
// the mark at fork. Only armed tasks are judged. Process names are never
// trusted. Tasks that already ran before the gadget loaded are armed from user
// space by writing the task storage map with a pidfd key.
//
// runc init for "exec" execs inside the container cgroup but still in the host
// mount namespace, so it is not armed. The command it execs after joining the
// container mount namespace is armed.

#ifndef __ENFORCEMENT_ARMING_H
#define __ENFORCEMENT_ARMING_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// Inode number of the mount namespace the container runtime runs in. 0 means
// the mount namespace of the global init task. Set it when the runtime does not
// run in init's mount namespace (for example a kind node).
const volatile __u64 host_mntns_id = 0;

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u32);
} armed_tasks SEC(".maps");

// A thread counts as armed when it or its thread group leader is armed. User
// space can arm only the leader on kernels without PIDFD_THREAD (< 6.9).
static __always_inline bool arming_task_armed(struct task_struct *task)
{
	__u32 *a = bpf_task_storage_get(&armed_tasks, task, 0, 0);
	struct task_struct *leader;

	if (a && *a)
		return true;
	leader = task->group_leader;
	if (!leader || leader == task)
		return false;
	a = bpf_task_storage_get(&armed_tasks, leader, 0, 0);
	return a && *a;
}

// Fault injection for tests only: fail every child mark at fork. Owners never
// set it in production.
const volatile bool arming_fail_fork_marks = false;

// Tracking faults per policy slot, for the owner's health check: a mark that
// failed for a task in a bound cgroup whose slot enforces. The array is
// preallocated, so counting never fails. A new instance starts at zero and
// arms the running tasks again.
#ifndef ARMING_FAULT_SLOTS
#define ARMING_FAULT_SLOTS 64
#endif

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, ARMING_FAULT_SLOTS);
	__type(key, __u32);
	__type(value, __u64);
} arming_faults SEC(".maps");

static __always_inline void arming_slot_fault(__u32 slot)
{
	__u64 *value = bpf_map_lookup_elem(&arming_faults, &slot);

	if (value)
		__sync_fetch_and_add(value, 1);
}

// arming_mark returns false when the task storage could not be allocated (memory
// pressure): the task then stays unarmed, and the caller handles the failure.
static __always_inline bool arming_mark(struct task_struct *task)
{
	__u32 *a = bpf_task_storage_get(&armed_tasks, task, 0,
					BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!a)
		return false;
	*a = 1;
	return true;
}

#define ARMING_MAX_ANCESTORS 64

// Cached mount namespace of the global init task (0 = not known yet).
__u64 arming_init_mntns = 0;

// arming_host_mntns returns host_mntns_id, or the mount namespace of the global
// init task. The real_parent chain of every task ends at the global init task
// (container processes are reparented to the runtime shim, which descends from
// it).
static __always_inline __u64 arming_host_mntns(struct task_struct *task)
{
	struct task_struct *t = task;

	if (host_mntns_id)
		return host_mntns_id;
	if (arming_init_mntns)
		return arming_init_mntns;

	for (int i = 0; i < ARMING_MAX_ANCESTORS; i++) {
		struct task_struct *parent = BPF_CORE_READ(t, real_parent);

		if (!parent || parent == t) {
			// Reached the top: cache the init task's namespace.
			arming_init_mntns =
				BPF_CORE_READ(t, nsproxy, mnt_ns, ns.inum);
			return arming_init_mntns;
		}
		t = parent;
	}
	// Tree deeper than the walk: no namespace inode is 0, so the task is
	// treated as outside the runtime namespace (armed), and nothing is cached.
	return 0;
}

// arming_on_exec runs after a successful exec (bprm_committed_creds).
// arming_on_exec returns false when a needed mark failed.
static __always_inline bool arming_on_exec(void)
{
	struct task_struct *task = bpf_get_current_task_btf();
	__u64 mntns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

	if (arming_task_armed(task))
		return true;
	if (mntns == arming_host_mntns(task))
		return true;
	return arming_mark(task);
}

#define ARMING_CLONE_THREAD 0x00010000ULL

// arming_on_fork runs in task_alloc: the child inherits the parent's mark.
// It returns false only when the parent is armed and the child's mark failed.
// An unarmed parent (for example a runtime helper) is out of scope, not a
// failure. A new thread whose group leader is armed is covered through the
// leader (see arming_task_armed), so its own mark is best effort.
static __always_inline bool arming_on_fork(struct task_struct *child,
					   __u64 clone_flags)
{
	struct task_struct *parent = bpf_get_current_task_btf();
	struct task_struct *leader;
	__u32 *a;

	if (!arming_task_armed(parent))
		return true;
	if (clone_flags & ARMING_CLONE_THREAD) {
		leader = parent->group_leader;
		a = leader ? bpf_task_storage_get(&armed_tasks, leader, 0, 0) :
			     NULL;
		if (a && *a) {
			if (!arming_fail_fork_marks)
				arming_mark(child);
			return true;
		}
	}
	if (arming_fail_fork_marks)
		return false;
	return arming_mark(child);
}

#endif /* __ENFORCEMENT_ARMING_H */
