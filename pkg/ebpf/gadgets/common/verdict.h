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
	// A lost deny whose new summary key did not fit (verdict_summaries
	// full): only the counters keep it.
	VERDICT_COUNT_SUMMARY_OVERFLOW = 6,
	VERDICT_COUNT_MAX = 7,
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
// is counted under its generation, slot, rule, hook, detail (privilege: the
// capability in bits 0-7, 255 for none, and the syscall from bit 8; file:
// the access kind; network: 0), mode and cgroup, with the first and last time (boot clock) and the first and last
// task. The task name is in the value, not the key, so a workload cannot
// make keys by renaming its tasks.
//
// The map is a plain hash: nothing is evicted, so a flood cannot remove the
// key of a hidden attempt once it exists. When the map is full, a new key is
// not added and the deny is counted in VERDICT_COUNT_SUMMARY_OVERFLOW (shown
// with VerdictsSuppressed; it also counts an insert that fails for lack of
// memory). A hidden attempt that shares the flood's key (same rule, hook and
// detail; under a default deny, the default rule) is counted in the flood's
// summary. Counts are approximate: an element the owner's drain deletes goes
// back to the per-CPU cache of the map's allocator and can be reused at once,
// so a program that looked it up just before the delete can add its count
// (and write last_*) to the new key in it, rarely another cgroup's. The
// counters stay exact.
// The owner drains it (enforcement.Bindings.DrainVerdictSummaries).
struct verdict_summary_key {
	__u64 cgroup;
	__u64 generation;
	__u32 slot;
	__u32 rule_id;
	__u32 hook;
	__u32 detail;
	__u8 is_default;
	__u8 mode;   // POLICY_MODE_AUDIT or POLICY_MODE_ENFORCE
	__u8 reason; // VERDICT_LOST_*
	__u8 pad[5];
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
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, VERDICT_SUMMARY_KEYS);
	__type(key, struct verdict_summary_key);
	__type(value, struct verdict_summary);
} verdict_summaries SEC(".maps");

// verdict_summarize adds one lost deny to its summary. Not inlined: the
// verdict functions are inlined into many hooks, and this keeps one copy.
// Five arguments at most: slot_rule is slot << 32 | rule id; flags: hook in
// bits 0-15, is_default bit 16, enforce bit 17, dropped (ring buffer full)
// bit 18.
static __noinline void verdict_summarize(__u64 generation, __u64 cgroup,
					 __u64 slot_rule, __u32 detail,
					 __u32 flags)
{
	struct verdict_summary_key key = {};
	struct verdict_summary init = {}, *s;
	__u64 now = bpf_ktime_get_boot_ns();
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	long err;

	key.cgroup = cgroup;
	key.generation = generation;
	key.slot = slot_rule >> 32;
	key.rule_id = (__u32)slot_rule;
	key.hook = flags & 0xffff;
	key.detail = detail;
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
		err = bpf_map_update_elem(&verdict_summaries, &key, &init,
					  BPF_NOEXIST);
		if (!err)
			return;
		// Added meanwhile on another CPU (-EEXIST); else the map is
		// full or out of memory.
		s = bpf_map_lookup_elem(&verdict_summaries, &key);
		if (!s) {
			verdict_count(VERDICT_COUNT_SUMMARY_OVERFLOW);
			return;
		}
	}
	__sync_fetch_and_add(&s->count, 1);
	// Not atomic: two CPUs may write close values; the summary keeps one.
	s->last_ns = now;
	s->last_pid = pid;
	bpf_get_current_comm(s->last_comm, sizeof(s->last_comm));
}

// verdict_lost counts a deny that has no event (reporting: the report limit
// allowed it, so the ring buffer was full) and adds it to its summary.
// detail: see struct verdict_summary_key.
static __always_inline void verdict_lost(bool reporting,
					 const struct policy_match *m,
					 __u64 generation, __u64 cgroup,
					 __u32 slot, __u32 hook, __u32 detail)
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
	verdict_summarize(generation, cgroup, (__u64)slot << 32 | m->rule_id,
			  detail, flags);
}

#endif /* __ENFORCEMENT_VERDICT_H */
