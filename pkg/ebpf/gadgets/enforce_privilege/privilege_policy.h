// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Kubescape Authors

// Policy map of the privilege section. All access to the map goes through this
// header (see ../common/policy.h for the resolution rules).

#ifndef __PRIVILEGE_POLICY_H
#define __PRIVILEGE_POLICY_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

// A subtree binding (a parent cgroup of containers) covers its descendant
// cgroups. Container bindings are exact.
#define BINDINGS_CGROUP_DEPTH 32

// Prefix of the section's pinned maps (../common/pin.h).
#define SANDBOX_SECTION sbx_priv_

#include "../common/bindings.h"
#include "../common/slots.h"
#include "../common/policy.h"
#include "../common/verdict.h"
#include "../common/arming.h"

// Two storage buffers per slot (../common/slots.h): twice the entries of
// one full set of slots.
#define PRIV_POLICY_MAX_ENTRIES 32768
#define PRIV_NAME_LEN 16

enum priv_kind : __u32 {
	// id 0: generation and policy mode (value.generation, value.mode).
	PRIV_KIND_META = 0,
	// id = target kind: default rank, rule id and origin id for that kind.
	PRIV_KIND_DEFAULT = 1,
	PRIV_KIND_SYSCALL = 2, // id: priv_syscall, qual: CLONE_NEW* flag or 0 (any)
	PRIV_KIND_CAPABILITY = 3, // id: capability number
	PRIV_KIND_MOUNT_FSTYPE = 4, // name: filesystem type
};

enum priv_fault_kind : __u32 {
	// A bound slot with no policy, or a task outside a Strict exact scope.
	PRIV_FAULT_STRUCTURAL = 0,
	// A lost arming mark in a Strict binding.
	PRIV_FAULT_TRACKING = 1,
};

struct priv_key {
	// Storage index (../common/slots.h), not the binding's slot.
	__u32 slot;
	__u32 kind;
	__u32 id;
	__u32 pad;
	__u64 qual;
	char name[PRIV_NAME_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PRIV_POLICY_MAX_ENTRIES);
	__uint(map_flags, BPF_F_RDONLY_PROG | BPF_F_NO_PREALLOC);
	__type(key, struct priv_key);
	__type(value, struct policy_value);
	SANDBOX_PINNED;
} SANDBOX_MAP(policy) SEC(".maps");

// Fault injection for tests only: every slot misses its META entry. Owners
// never set it in production.
const volatile bool policy_fail_headers = false;

// priv_header returns the META entry of the slot's active publication for a
// task in a bound cgroup, or NULL when nothing must be judged. It also returns
// the binding flags and the storage index of that publication: use it for
// every lookup of the call.
//
// A bound cgroup whose slot was never published (or has no META entry) is a
// structural fault, not an unbound task: it counts as a section error, and
// *faulted is true with the slot's generation (0 when it has no policy), for
// the caller to report. For a Strict binding it is also a slot fault, and
// *fault is true: the hook must deny. An Audit binding allows. A task outside
// a Strict binding's exact scope (BINDING_OUTSIDE_SCOPE) is the same fault.
static __always_inline struct policy_value *priv_header(__u64 *cgroup,
						       __u32 *slot,
						       __u32 *storage,
						       __u32 *flags,
						       bool *fault,
						       bool *faulted,
						       __u64 *generation)
{
	struct priv_key key = { .kind = PRIV_KIND_META };
	struct policy_value *header = NULL;

	*fault = false;
	*faulted = false;
	*generation = 0;
	if (!binding_lookup(cgroup, slot, flags))
		return NULL;
	if (slot_storage(*slot, storage, generation)) {
		key.slot = *storage;
		header = bpf_map_lookup_elem(&SANDBOX_MAP(policy), &key);
	}
	if (!header || policy_fail_headers || (*flags & BINDING_OUTSIDE_SCOPE)) {
		verdict_count(VERDICT_COUNT_SECTION_ERROR);
		*faulted = true;
		if (*flags & BINDING_STRICT) {
			arming_slot_fault(*slot);
			*fault = true;
		}
		return NULL;
	}
	if (header->mode == POLICY_MODE_OFF)
		return NULL;
	return header;
}

// priv_slot_generation is the generation of the slot's active publication,
// or 0 when it has none.
static __always_inline __u64 priv_slot_generation(__u32 slot)
{
	__u64 generation = 0;
	__u32 storage;

	if (!slot_storage(slot, &storage, &generation))
		return 0;
	return generation;
}

static __always_inline void priv_consider(const struct priv_key *key,
					  struct policy_match *m)
{
	policy_take(m, bpf_map_lookup_elem(&SANDBOX_MAP(policy), key), false);
}

// priv_finish_kind applies the default of kind when no rule of that kind
// matched. Each kind resolves on its own; merge kinds with policy_merge.
static __always_inline void priv_finish_kind(__u32 storage, __u32 kind,
					    struct policy_match *m)
{
	struct priv_key key = { .slot = storage, .kind = PRIV_KIND_DEFAULT, .id = kind };

	if (m->rank == POLICY_RANK_NONE)
		policy_take(m, bpf_map_lookup_elem(&SANDBOX_MAP(policy), &key), true);
}

#endif /* __PRIVILEGE_POLICY_H */
