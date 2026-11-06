// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Kubescape Authors

// Policy resolution shared by the enforcement gadgets.
//
// The program is fixed; the native owner writes the section's policy map and
// freezes it before any binding is written. A rule change starts a replacement
// gadget instance, and the generation identifies the instance's policy. Modes
// use the enforce_exec encoding.
//
// Each policy value holds a rank. The compiler folds every rule that hits one
// key into the most limiting rank, and the program takes the maximum over every
// key a hook touches, so resolution is: explicit deny > allow > section default,
// independent of rule order, with one mode per rule. Key layouts are per section.

#ifndef __ENFORCEMENT_POLICY_H
#define __ENFORCEMENT_POLICY_H

#include <vmlinux.h>

#define POLICY_MODE_OFF 0
#define POLICY_MODE_AUDIT 1
#define POLICY_MODE_ENFORCE 2

enum policy_rank : __u8 {
	POLICY_RANK_NONE = 0,
	POLICY_RANK_ALLOW = 1,
	POLICY_RANK_DENY_AUDIT = 2,
	POLICY_RANK_DENY_ENFORCE = 3,
};

struct policy_value {
	__u8 rank;
	__u8 pad[3];
	// Rule and origin ids index name tables kept by the native owner. 0 = none.
	__u32 rule_id;
	__u32 origin_id;
	// Set only on the section's header entry.
	__u32 mode;
	__u64 generation;
};

// The result of combining every entry a hook touched.
struct policy_match {
	__u8 rank;
	__u8 is_default;
	__u32 rule_id;
	__u32 origin_id;
};

// policy_take keeps v in m when it is more limiting than what m holds.
static __always_inline void policy_take(struct policy_match *m,
					const struct policy_value *v,
					bool is_default)
{
	if (!v || v->rank <= m->rank)
		return;
	m->rank = v->rank;
	m->is_default = is_default;
	m->rule_id = v->rule_id;
	m->origin_id = v->origin_id;
}

static __always_inline void policy_merge(struct policy_match *dst,
					 const struct policy_match *src)
{
	if (src->rank > dst->rank)
		*dst = *src;
}

#endif /* __ENFORCEMENT_POLICY_H */
