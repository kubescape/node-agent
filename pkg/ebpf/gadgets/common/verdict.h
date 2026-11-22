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
	VERDICT_COUNT_SECTION_ERROR = 4, // failed arming marks, structural faults
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

	// Atomic: a preemptible kernel can run two hooks on one CPU (see
	// arming.h).
	if (value)
		__sync_fetch_and_add(value, 1);
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
	__sync_fetch_and_add(&window->attempts, 1);
	return true;
}

// Summary of the rule decisions the kernel could not report: past the report
// limit, or with a full ring buffer. Without it, one real attempt inside a
// flood of cheap denied actions leaves no trace but a counter. Each lost deny
// is counted under its generation, slot, rule, hook, mode and cgroup, with
// the first and last time (boot clock) and the first and last task. The key
// has no field the workload controls (the task name is in the value), so a
// flood cannot create keys to push a hidden attempt of another rule out of
// the LRU: the number of keys is bounded by the policies and bindings. The
// owner drains it (enforcement.Bindings.DrainVerdictSummaries). Counts are
// approximate: concurrent updates of one key, and an update racing the
// owner's delete, can lose a deny (the counters keep the number). A deny that
// is reported in an event is never counted here.
struct verdict_summary_key {
	__u64 cgroup;
	__u64 generation;
	__u32 slot;
	__u32 rule_id;
	__u32 hook;
	__u8 is_default;
	__u8 mode;   // POLICY_MODE_AUDIT or POLICY_MODE_ENFORCE
	__u8 reason; // VERDICT_LOST_*
	__u8 pad;
};

struct verdict_summary {
	__u64 count;
	__u64 first_ns;
	__u64 last_ns;
	__u32 first_pid;
	__u32 last_pid;
	char first_comm[16];
	char last_comm[16];
};

#define VERDICT_LOST_RATE_LIMITED 1
#define VERDICT_LOST_DROPPED 2
#define VERDICT_SUMMARY_KEYS 4096

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, VERDICT_SUMMARY_KEYS);
	__type(key, struct verdict_summary_key);
	__type(value, struct verdict_summary);
} verdict_summaries SEC(".maps");

// verdict_summarize adds one lost deny to its summary. Not inlined: the
// verdict functions are inlined into many hooks, and this keeps one copy.
// flags: hook in bits 0-15, is_default bit 16, enforce bit 17, dropped
// (ring buffer full) bit 18 (five arguments at most).
static __noinline void verdict_summarize(__u64 generation, __u64 cgroup,
					 __u32 slot, __u32 rule_id,
					 __u32 flags)
{
	struct verdict_summary_key key = {};
	struct verdict_summary init = {}, *s;
	__u64 now = bpf_ktime_get_boot_ns();
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	key.cgroup = cgroup;
	key.generation = generation;
	key.slot = slot;
	key.rule_id = rule_id;
	key.hook = flags & 0xffff;
	key.is_default = (flags >> 16) & 1;
	key.mode = (flags >> 17) & 1 ? POLICY_MODE_ENFORCE : POLICY_MODE_AUDIT;
	key.reason = (flags >> 18) & 1 ? VERDICT_LOST_DROPPED :
					 VERDICT_LOST_RATE_LIMITED;
	s = bpf_map_lookup_elem(&verdict_summaries, &key);
	if (!s) {
		init.count = 1;
		init.first_ns = now;
		init.last_ns = now;
		init.first_pid = pid;
		init.last_pid = pid;
		bpf_get_current_comm(init.first_comm, sizeof(init.first_comm));
		__builtin_memcpy(init.last_comm, init.first_comm,
				 sizeof(init.last_comm));
		if (!bpf_map_update_elem(&verdict_summaries, &key, &init,
					 BPF_NOEXIST))
			return;
		// Added meanwhile on another CPU.
		s = bpf_map_lookup_elem(&verdict_summaries, &key);
		if (!s)
			return;
	}
	__sync_fetch_and_add(&s->count, 1);
	// Not atomic: two CPUs may write close values; the summary keeps one.
	s->last_ns = now;
	s->last_pid = pid;
	bpf_get_current_comm(s->last_comm, sizeof(s->last_comm));
}

// verdict_lost counts a deny that has no event (reporting: the report limit
// allowed it, so the ring buffer was full) and adds it to its summary.
static __always_inline void verdict_lost(bool reporting,
					 const struct policy_match *m,
					 __u64 generation, __u64 cgroup,
					 __u32 slot, __u32 hook)
{
	__u32 flags = hook & 0xffff;

	verdict_count(reporting ? VERDICT_COUNT_DROPPED :
				  VERDICT_COUNT_RATE_LIMITED);
	if (m->is_default)
		flags |= 1U << 16;
	if (m->rank == POLICY_RANK_DENY_ENFORCE)
		flags |= 1U << 17;
	if (reporting)
		flags |= 1U << 18;
	verdict_summarize(generation, cgroup, slot, m->rule_id, flags);
}

#endif /* __ENFORCEMENT_VERDICT_H */
