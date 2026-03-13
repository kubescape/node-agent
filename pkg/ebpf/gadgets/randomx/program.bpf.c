// Kernel types definitions
#include <vmlinux.h>

// eBPF helpers signatures
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// Inspektor Gadget headers
#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/macros.h>
#include <gadget/filter.h>
#include <gadget/types.h>
#include <gadget/mntns.h>

#include "program.h"
#include "upper_layer.h"
#include "exe_path.h"

#if defined(__TARGET_ARCH_x86)

// ============================================================================
// Crypto miner detection via two independent signals:
//
// Signal 1 — sched_switch preemptions (primary, works on all kernels):
//   Crypto miners are CPU-bound: they get preempted (prev_state == TASK_RUNNING)
//   on nearly every context switch. Normal I/O-bound services yield voluntarily.
//   Threshold: 10000 preemptions in 30 seconds (~333/sec sustained).
//
// Signal 2 — x86_fpu_regs_deactivated frequency (secondary, older kernels):
//   On kernels where FPU lazy restore hasn't been optimized away, crypto miners
//   generate a high rate of FPU deactivation events.
//   Threshold: 500000 events in 30 seconds (~16667/sec sustained).
//   Set very high because on modern kernels this tracepoint fires for ALL
//   FPU-using processes. On older kernels it's more selective.
//
// Either signal crossing its threshold fires the alert (one per container).
// ============================================================================

#define PREEMPT_THRESHOLD  10000
// FPU threshold set very high — on modern kernels (6.x) the FPU tracepoint
// fires for ALL FPU-using processes, making it noisy. On older kernels where
// it fires more selectively, this still works as a backup signal.
#define FPU_THRESHOLD     500000
// 30 seconds in nanoseconds
#define WINDOW_NS          30000000000ULL

struct mntns_cache {
    u64 window_start;
    u64 fpu_count;
    u64 preempt_count;
    bool alerted;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, struct mntns_cache);
} mntns_event_count SEC(".maps");

// Ring buffer for events — 256KB.
GADGET_TRACER_MAP(events, 1024 * 256);

// Define the tracer (links the "randomx" datasource to the event struct).
GADGET_TRACER(randomx, events, event);

// ---------------------------------------------------------------------------
// Helper: reset the sliding window if it expired.
// Returns true if the window was reset (caller should return 0 early).
// ---------------------------------------------------------------------------
static __always_inline bool maybe_reset_window(
    struct mntns_cache *cache, u64 now, u64 mntns_id)
{
    if (now - cache->window_start > WINDOW_NS) {
        cache->window_start = now;
        cache->fpu_count = 0;
        cache->preempt_count = 0;
        bpf_map_update_elem(&mntns_event_count, &mntns_id, cache, BPF_ANY);
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Helper: check if either threshold is met and emit the alert event.
// Returns true if alert was emitted.
// ---------------------------------------------------------------------------
static __always_inline bool maybe_alert(
    struct mntns_cache *cache, u64 mntns_id, void *ctx)
{
    bool fpu_hit = cache->fpu_count >= FPU_THRESHOLD;
    bool preempt_hit = cache->preempt_count >= PREEMPT_THRESHOLD;

    if (!fpu_hit && !preempt_hit)
        return false;

    // Mark alerted so no further events are emitted for this container.
    cache->alerted = true;
    bpf_map_update_elem(&mntns_event_count, &mntns_id, cache, BPF_ANY);

    struct event *event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event)
        return true; // alerted flag is set, nothing more to do

    gadget_process_populate(&event->proc);
    event->upper_layer = has_upper_layer();
    read_exe_path(event->exepath, sizeof(event->exepath));
    event->timestamp_raw = bpf_ktime_get_boot_ns();

    bpf_printk("randomx: ALERT mntns=%llu fpu=%llu preempt=%llu",
               mntns_id, cache->fpu_count, cache->preempt_count);

    gadget_submit_buf(ctx, &events, event, sizeof(*event));
    return true;
}

// ===========================================================================
// Signal 1: sched_switch — count involuntary preemptions per container.
//
// prev_state == 0 (TASK_RUNNING) means the task wanted to keep running but
// was preempted by the scheduler.  Crypto miners are almost always in this
// state because they never voluntarily sleep.
// ===========================================================================
SEC("tracepoint/sched/sched_switch")
int tracepoint__sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    // Fast path: ignore voluntary context switches (task yielded / slept).
    // This filters out ~60-80% of events before any map lookup.
    long prev_state = BPF_CORE_READ(ctx, prev_state);
    if (prev_state != 0)
        return 0;

    if (gadget_should_discard_data_current())
        return 0;

    u64 mntns_id = gadget_get_current_mntns_id();
    u64 now = bpf_ktime_get_ns();

    struct mntns_cache *cache = bpf_map_lookup_elem(&mntns_event_count, &mntns_id);
    if (!cache) {
        struct mntns_cache new_cache = {};
        new_cache.window_start = now;
        new_cache.preempt_count = 1;
        bpf_map_update_elem(&mntns_event_count, &mntns_id, &new_cache, BPF_ANY);
        return 0;
    }

    if (cache->alerted)
        return 0;

    if (maybe_reset_window(cache, now, mntns_id))
        return 0;

    cache->preempt_count++;
    bpf_map_update_elem(&mntns_event_count, &mntns_id, cache, BPF_ANY);
    maybe_alert(cache, mntns_id, ctx);

    return 0;
}

// ===========================================================================
// Signal 2: x86_fpu_regs_deactivated — count FPU save events per container.
//
// On older kernels (pre-6.x) the FPU deactivation tracepoint fires reliably
// for FPU-heavy processes.  On newer kernels with eager-FPU optimizations,
// CPU-bound processes may NOT generate these events, so this serves as a
// secondary signal that improves detection on older kernels.
// ===========================================================================
SEC("tracepoint/x86_fpu/x86_fpu_regs_deactivated")
int tracepoint__x86_fpu_regs_deactivated(struct trace_event_raw_x86_fpu *ctx)
{
    if (gadget_should_discard_data_current())
        return 0;

    u64 mntns_id = gadget_get_current_mntns_id();
    u64 now = bpf_ktime_get_ns();

    struct mntns_cache *cache = bpf_map_lookup_elem(&mntns_event_count, &mntns_id);
    if (!cache) {
        struct mntns_cache new_cache = {};
        new_cache.window_start = now;
        new_cache.fpu_count = 1;
        bpf_map_update_elem(&mntns_event_count, &mntns_id, &new_cache, BPF_ANY);
        return 0;
    }

    if (cache->alerted)
        return 0;

    if (maybe_reset_window(cache, now, mntns_id))
        return 0;

    cache->fpu_count++;
    bpf_map_update_elem(&mntns_event_count, &mntns_id, cache, BPF_ANY);
    maybe_alert(cache, mntns_id, ctx);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

#endif // defined(__TARGET_ARCH_x86)
