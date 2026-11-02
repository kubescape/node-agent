// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Kubescape Authors

// Verdict reporting shared by the enforcement gadgets. Names, order, limits and
// counter slots follow the enforce_exec gadget, so one consumer decodes both.
// Reporting is limited to 100 attempts per CPU per second; enforcement is never
// throttled.

#ifndef __ENFORCEMENT_VERDICT_H
#define __ENFORCEMENT_VERDICT_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "policy.h"

// First fields of every verdict event, in enforce_exec order. mode: 1 audit,
// 2 enforce.
#define VERDICT_BASE_FIELDS \
	__u64 generation;   \
	__u64 cgroup;       \
	__u32 deny;         \
	__u32 mode

#define VERDICT_FILL_BASE(e, m, gen, cgroup_id)                         \
	do {                                                            \
		(e)->generation = (gen);                                \
		(e)->cgroup = (cgroup_id);                              \
		(e)->deny = (m)->rank >= POLICY_RANK_DENY_AUDIT;        \
		(e)->mode = (m)->rank == POLICY_RANK_DENY_ENFORCE ?     \
				    POLICY_MODE_ENFORCE :               \
				    POLICY_MODE_AUDIT;                  \
	} while (0)

// Counter slots, as in enforce_exec.
enum verdict_counter {
	VERDICT_COUNT_DENIED = 0, // deny decisions, audit and enforce
	VERDICT_COUNT_SUBMITTED = 1,
	VERDICT_COUNT_DROPPED = 2,
	VERDICT_COUNT_ALLOWED = 3,
	VERDICT_COUNT_SECTION_ERROR = 4, // privilege: failed arming marks
	VERDICT_COUNT_RATE_LIMITED = 5,
	VERDICT_COUNT_MAX = 6,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, VERDICT_COUNT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

static __always_inline void verdict_count(__u32 key)
{
	__u64 *value = bpf_map_lookup_elem(&counters, &key);

	if (value)
		(*value)++;
}

#define VERDICT_REPORTS_PER_SECOND 100

struct report_window {
	__u64 second;
	__u32 attempts;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct report_window);
} report_windows SEC(".maps");

static __always_inline bool verdict_report_allowed(void)
{
	__u32 zero = 0;
	struct report_window *window =
		bpf_map_lookup_elem(&report_windows, &zero);
	__u64 second;

	if (!window)
		return false;
	second = bpf_ktime_get_ns() / 1000000000;
	if (window->second != second) {
		window->second = second;
		window->attempts = 0;
	}
	if (window->attempts >= VERDICT_REPORTS_PER_SECOND)
		return false;
	window->attempts++;
	return true;
}

#endif /* __ENFORCEMENT_VERDICT_H */
