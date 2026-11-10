// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Kubescape Authors

// Policy slots of a long-lived node-wide enforcement gadget instance. A slot
// (the slot of a binding) has two storage buffers. The section's policy maps
// are keyed by the storage index slot * 2 + buffer, not by the slot. The owner
// writes a new policy into the inactive buffer, then flips the slot's state in
// one map write; it deletes the old buffer after a quarantine. A hook reads
// the state once (slot_storage) and uses that one storage index for every
// lookup of the call, so one call never mixes two versions of a slot.

#ifndef __ENFORCEMENT_SLOTS_H
#define __ENFORCEMENT_SLOTS_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define SANDBOX_SLOTS 64
#define SANDBOX_STORAGE (SANDBOX_SLOTS * 2)

struct slot_state {
	// Active buffer: 0 or 1.
	__u32 active;
	__u32 pad;
	// Generation of the active publication; 0 = never published (a bound
	// slot with no policy is a structural fault).
	__u64 generation;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SANDBOX_SLOTS);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct slot_state);
} sandbox_slot_state SEC(".maps");

// slot_storage returns the storage index of the slot's active publication and
// its generation, or false when the slot was never published.
static __always_inline bool slot_storage(__u32 slot, __u32 *storage,
					 __u64 *generation)
{
	const struct slot_state *s =
		bpf_map_lookup_elem(&sandbox_slot_state, &slot);

	if (!s || !s->generation)
		return false;
	*storage = slot * 2 + (s->active & 1);
	*generation = s->generation;
	return true;
}

#endif /* __ENFORCEMENT_SLOTS_H */
