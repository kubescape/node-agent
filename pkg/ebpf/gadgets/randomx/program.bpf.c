// Kernel types definitions
#include <vmlinux.h>

// eBPF helpers signatures
// Check https://man7.org/linux/man-pages/man7/bpf-helpers.7.html to learn
// more about different available helpers
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// Inspektor Gadget buffer
#include <gadget/buffer.h>
// Helpers to handle common data
#include <gadget/common.h>
// Inspektor Gadget macros
#include <gadget/macros.h>
// Inspektor Gadget filtering
#include <gadget/filter.h>
// Inspektor Gadget types
#include <gadget/types.h>
// Inspektor Gadget mntns
#include <gadget/mntns.h>

#include "program.h"
#include "upper_layer.h"
#include "exe_path.h"

#if defined(__TARGET_ARCH_x86)

#define TARGET_RANDOMX_EVENTS_COUNT 5
// 5 seconds in nanoseconds
#define MAX_NS_BETWEEN_EVENTS 5000000000ULL 

// This struct will hold the state for each mount namespace
struct mntns_cache {
    u64 timestamp;
    u64 events_count;
    bool alerted;
};

// A map to store the cache per mntns_id.
// key: mntns_id (u64), value: struct mntns_cache
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024); 
    __type(key, u64);
    __type(value, struct mntns_cache);
} mntns_event_count SEC(".maps");

// events is the name of the buffer map and 1024 * 256 (256KB) is its size.
GADGET_TRACER_MAP(events, 1024 * 256);

// Define a tracer
GADGET_TRACER(randomx, events, event);

// Utilize the kernel version provided by libbpf. (kconfig must be present).
extern int LINUX_KERNEL_VERSION __kconfig;

#if LINUX_KERNEL_VERSION <= KERNEL_VERSION(5, 15, 0)
struct old_fpu {
    unsigned int last_cpu;
    unsigned char initialized;
    long: 24;
    long: 64;
    long: 64;
    long: 64;
    long: 64;
    long: 64;
    long: 64;
    long: 64;
    union fpregs_state state;
};
#endif

SEC("tracepoint/x86_fpu/x86_fpu_regs_deactivated")
int tracepoint__x86_fpu_regs_deactivated(struct trace_event_raw_x86_fpu *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }

    u64 mntns_id;
    mntns_id = gadget_get_current_mntns_id();
    struct mntns_cache *cache;
    cache = bpf_map_lookup_elem(&mntns_event_count, &mntns_id);

    u64 now = bpf_ktime_get_ns();

    if (!cache) {
        // First event for this mntns. Create a new entry.
        struct mntns_cache new_cache = {};
        new_cache.timestamp = now;
        new_cache.events_count = 1;
        new_cache.alerted = false;
        bpf_map_update_elem(&mntns_event_count, &mntns_id, &new_cache, BPF_ANY);
        return 0; // Don't send an event yet
    }

    // If we have already sent an alert for this mntns, do nothing.
    if (cache->alerted) {
        return 0;
    }

    // Check if the last event was too long ago and reset if necessary.
    if (now - cache->timestamp > MAX_NS_BETWEEN_EVENTS) {
        cache->timestamp = now;
        cache->events_count = 1;
        bpf_map_update_elem(&mntns_event_count, &mntns_id, cache, BPF_ANY);
        return 0; // Don't send an event yet
    }
    
    // Increment the count. Using bpf_map_update_elem is not atomic, but for
    // this use case (a single CPU tracepoint), it's safe.
    cache->events_count++;
    cache->timestamp = now; // Update timestamp with the latest event

    // Check if we have seen enough events
    if (cache->events_count <= TARGET_RANDOMX_EVENTS_COUNT) {
        // Not enough events yet, just update the map and exit.
        bpf_map_update_elem(&mntns_event_count, &mntns_id, cache, BPF_ANY);
        return 0;
    }

    // --- Threshold has been reached! ---
    // We only reach this point ONCE per mntns.

    // Mark as alerted to prevent sending more events for this mntns.
    cache->alerted = true;
    bpf_map_update_elem(&mntns_event_count, &mntns_id, cache, BPF_ANY);

    struct event *event;
    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event) {
        return 0;
    }
    
    // Populate the event with data. This code is the same as before.
    gadget_process_populate(&event->proc);

    void *fpu = BPF_CORE_READ(ctx, fpu);
    if (fpu == NULL) {
        gadget_discard_buf(event);
        return 0;
    }

    u32 mxcsr;
    if(LINUX_KERNEL_VERSION <= KERNEL_VERSION(5, 15, 0)) {
        bpf_probe_read_kernel(&mxcsr, sizeof(mxcsr), &((struct old_fpu*)fpu)->state.xsave.i387.mxcsr);
    } else {
        mxcsr = BPF_CORE_READ((struct fpu*)fpu, fpstate, regs.xsave.i387.mxcsr);
    }
    
    int fpcr = (mxcsr & 0x6000) >> 13;
    if (fpcr != 0) {
        event->upper_layer = has_upper_layer();
        read_exe_path(event->exepath, sizeof(event->exepath));

        event->timestamp_raw = bpf_ktime_get_boot_ns();

        gadget_submit_buf(ctx, &events, event, sizeof(*event));
    } else {
        gadget_discard_buf(event);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

#endif // defined(__TARGET_ARCH_x86)