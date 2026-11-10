// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Kubescape Authors

// Policy slots of a long-lived node-wide enforcement gadget instance. A slot
// (the slot of a binding) has two storage buffers. The section's policy maps
// are keyed by the storage index slot * 2 + buffer, not by the slot. The owner
// writes a new policy into the inactive buffer, then flips the slot's state in
// one map write; it deletes the old buffer after a quarantine. A hook reads
// the state with one load (slot_storage) and uses that one storage index for
// every lookup of the call, so one call never mixes two versions of a slot.

#ifndef __ENFORCEMENT_SLOTS_H
#define __ENFORCEMENT_SLOTS_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "pin.h"

#define SANDBOX_SLOTS 64
#define SANDBOX_STORAGE (SANDBOX_SLOTS * 2)

// One 8-byte value, read with one load: generation << 1 | active buffer. A
// generation of 0 means never published (a bound slot with no policy is a
// structural fault).
struct slot_state {
	__u64 state;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SANDBOX_SLOTS);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct slot_state);
	SANDBOX_PINNED;
} SANDBOX_MAP(slot_state) SEC(".maps");

// sandbox_slot_state_read returns the slot's state word, 0 when the slot has
// none. A global function: the verifier checks it once, not at each call
// site, which keeps the hooks that look up several slots small.
__noinline __u64 sandbox_slot_state_read(__u32 slot)
{
	const struct slot_state *s =
		bpf_map_lookup_elem(&SANDBOX_MAP(slot_state), &slot);

	if (!s)
		return 0;
	return *(volatile const __u64 *)&s->state;
}

// sandbox_slot_storage returns the storage index of the slot's active
// publication, or SANDBOX_STORAGE when the slot was never published: no
// policy map has an entry there, so a lookup simply misses (a structural
// fault for a bound slot). A global function with no branch for the caller,
// which keeps large hooks within the verifier's limits.
__noinline __u32 sandbox_slot_storage(__u32 slot)
{
	__u64 state = sandbox_slot_state_read(slot);

	if (!(state >> 1))
		return SANDBOX_STORAGE;
	return slot * 2 + (__u32)(state & 1);
}

// slot_storage returns the storage index of the slot's active publication and
// its generation, or false when the slot was never published.
static __always_inline bool slot_storage(__u32 slot, __u32 *storage,
					 __u64 *generation)
{
	__u64 state = sandbox_slot_state_read(slot);

	if (!(state >> 1))
		return false;
	*storage = slot * 2 + (__u32)(state & 1);
	*generation = state >> 1;
	return true;
}

#endif /* __ENFORCEMENT_SLOTS_H */
