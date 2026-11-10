// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Kubescape Authors

// Policy maps and the decision function of the network section. The decision
// needs only a slot, a destination and a protocol. Nothing here reads a hook
// context or the current task. See ../common/policy.h for the ranks.
//
// Maps, written by the native owner per publication (../common/slots.h). They
// are keyed by the storage index of a slot's buffer, not by the slot:
// - net_slots:  storage -> merged default, mode, generation and the policies
//               whose default denies in enforce mode (written last).
// - net_prefix: LPM trie (storage, 16-byte address) -> rule list index. IPv4 is
//               stored IPv4-mapped (::ffff:a.b.c.d). The trie returns only the
//               longest prefix, so the compiler copies every rule that covers a
//               prefix into its list; an except is a more specific prefix whose
//               list lacks that deny.
// - net_rules:  rule list index -> up to NET_LIST_LEN rules (port range,
//               protocol, rank, policy index). A pool shared by every
//               publication; the owner allocates the indexes.

#ifndef __NETWORK_POLICY_H
#define __NETWORK_POLICY_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "../common/policy.h"
#include "../common/slots.h"

// Logical slots (fault counters) and storage buffers (policy maps). The
// prefix and list limits are per set of buffers; the maps hold two sets.
#define NET_MAX_SLOTS SANDBOX_SLOTS
#define NET_STORAGE SANDBOX_STORAGE
#define NET_MAX_PREFIXES 16384
#define NET_MAX_LISTS 1024
#define NET_LIST_LEN 32

#define NET_IPPROTO_TCP 6
#define NET_IPPROTO_UDP 17
#define NET_IPPROTO_UDPLITE 136
#define NET_IPPROTO_MPTCP 262

// Rule protocol. A rule with NET_PROTO_ANY matches every protocol.
enum net_proto : __u8 {
	NET_PROTO_ANY = 0,
	NET_PROTO_TCP = 1,
	NET_PROTO_UDP = 2,
	NET_PROTO_OTHER = 3, // never in a rule: matches NET_PROTO_ANY rules only
};

struct net_slot {
	// rank: merged default; rule_id 1 ("default"); mode: 0 = slot not
	// judged; generation of the instance.
	struct policy_value def;
	// Bit i: policy i of the slot has an enforce default deny (merge rule 5).
	__u32 deny_enforce_docs;
	__u32 pad;
};

struct net_prefix_key {
	__u32 prefixlen; // 32 (storage) + address bits
	__u32 slot; // storage index
	__u8 addr[16];
};

struct net_rule {
	__u16 port_lo; // inclusive range, host byte order; 0-65535 = any
	__u16 port_hi;
	__u8 proto; // enum net_proto
	__u8 rank; // enum policy_rank
	__u8 doc; // index of the rule's policy in the slot
	__u8 pad;
	__u32 rule_id;
	__u32 origin_id;
};

struct net_list {
	__u32 len;
	__u32 pad;
	struct net_rule rules[NET_LIST_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NET_STORAGE);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct net_slot);
	SANDBOX_PINNED;
} SANDBOX_MAP(net_slots) SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 2 * NET_MAX_PREFIXES);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG);
	__type(key, struct net_prefix_key);
	__type(value, __u32);
	SANDBOX_PINNED;
} SANDBOX_MAP(net_prefix) SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2 * NET_MAX_LISTS);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct net_list);
	SANDBOX_PINNED;
} SANDBOX_MAP(net_rules) SEC(".maps");

// Faults per slot, for the owner's health check (the layout of arming_faults
// in ../common/arming.h): a Strict binding whose slot has no policy, or a task
// outside a Strict binding's exact scope. Preallocated, so counting never
// fails.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NET_MAX_SLOTS);
	__type(key, __u32);
	__type(value, __u64);
	SANDBOX_PINNED;
} SANDBOX_MAP(net_faults) SEC(".maps");

static __always_inline void net_slot_fault(__u32 slot)
{
	__u64 *value = bpf_map_lookup_elem(&SANDBOX_MAP(net_faults), &slot);

	if (value)
		__sync_fetch_and_add(value, 1);
}

// net_proto_of maps an IP protocol number to the rule protocol.
static __always_inline __u8 net_proto_of(__u16 ipproto)
{
	switch (ipproto) {
	case NET_IPPROTO_TCP:
	case NET_IPPROTO_MPTCP:
		return NET_PROTO_TCP;
	case NET_IPPROTO_UDP:
	case NET_IPPROTO_UDPLITE:
		return NET_PROTO_UDP;
	}
	return NET_PROTO_OTHER;
}

// net_decide resolves one destination (16-byte address, IPv4 mapped; port in
// host byte order) for the publication at storage into m: the most limiting matching rule (deny
// enforce > deny audit > allow), else the slot default. When every matching
// rule denies, the enforce default deny of each policy without a matching rule
// still applies, so an audit policy never weakens another policy.
static __always_inline void net_decide(__u32 storage, const struct net_slot *s,
				       const __u8 *addr, __u16 port, __u8 proto,
				       struct policy_match *m)
{
	struct net_prefix_key key = { .prefixlen = 32 + 128, .slot = storage };
	const struct net_list *list = NULL;
	__u32 *index;
	__u32 docs = 0;
	bool allowed = false;

	__builtin_memcpy(key.addr, addr, 16);
	index = bpf_map_lookup_elem(&SANDBOX_MAP(net_prefix), &key);
	if (index)
		list = bpf_map_lookup_elem(&SANDBOX_MAP(net_rules), index);
	if (list) {
		for (__u32 i = 0; i < NET_LIST_LEN; i++) {
			const struct net_rule *r;

			if (i >= list->len)
				break;
			r = &list->rules[i];
			if (r->proto != NET_PROTO_ANY && r->proto != proto)
				continue;
			if (port < r->port_lo || port > r->port_hi)
				continue;
			docs |= 1U << (r->doc & 31);
			if (r->rank == POLICY_RANK_ALLOW)
				allowed = true;
			if (r->rank > m->rank) {
				m->rank = r->rank;
				m->is_default = 0;
				m->rule_id = r->rule_id;
				m->origin_id = r->origin_id;
			}
		}
	}
	if (m->rank == POLICY_RANK_NONE) {
		policy_take(m, &s->def, true);
		return;
	}
	if (!allowed && (s->deny_enforce_docs & ~docs) &&
	    m->rank < POLICY_RANK_DENY_ENFORCE) {
		m->rank = POLICY_RANK_DENY_ENFORCE;
		m->is_default = 1;
		m->rule_id = s->def.rule_id;
		m->origin_id = s->def.origin_id;
	}
}

#endif /* __NETWORK_POLICY_H */
