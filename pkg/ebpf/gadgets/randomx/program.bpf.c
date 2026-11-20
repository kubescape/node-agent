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
};

struct mntns_cache_key {
    u64 mntns_id;
    u64 cgroup_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024); 
    __type(key, struct mntns_cache_key);
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

    void *fpu = BPF_CORE_READ(ctx, fpu);
    if (fpu == NULL) {
        return 0;
    }

    u32 mxcsr;
    if(LINUX_KERNEL_VERSION <= KERNEL_VERSION(5, 15, 0)) {
        bpf_probe_read_kernel(&mxcsr, sizeof(mxcsr), &((struct old_fpu*)fpu)->state.xsave.i387.mxcsr);
    } else {
        mxcsr = BPF_CORE_READ((struct fpu*)fpu, fpstate, regs.xsave.i387.mxcsr);
    }

    if (((mxcsr & 0x6000) >> 13) == 0) {
        return 0;
    }

    struct mntns_cache_key key = {};
    key.mntns_id = gadget_get_current_mntns_id();
    if (key.mntns_id == 0) {
        return 0;
    }
    key.cgroup_id = bpf_get_current_cgroup_id();
    struct mntns_cache *cache;
    cache = bpf_map_lookup_elem(&mntns_event_count, &key);

    u64 now = bpf_ktime_get_ns();

    if (!cache) {
        struct mntns_cache fresh = {.timestamp = now, .events_count = 1};
        bpf_map_update_elem(&mntns_event_count, &key, &fresh, BPF_NOEXIST);
        return 0;
    }

    if ((s64)(now - cache->timestamp) > (s64)MAX_NS_BETWEEN_EVENTS) {
        cache->events_count = 0;
    }
    cache->timestamp = now;

    if (__sync_fetch_and_add(&cache->events_count, 1) != TARGET_RANDOMX_EVENTS_COUNT) {
        return 0;
    }

    struct event *event;
    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event) {
        return 0;
    }
    
    // Populate the event with data.
    gadget_process_populate(&event->proc);
    event->upper_layer = has_upper_layer();
    read_exe_path(event->exepath, sizeof(event->exepath));
    event->timestamp_raw = bpf_ktime_get_boot_ns();

    gadget_submit_buf(ctx, &events, event, sizeof(*event));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

#endif // defined(__TARGET_ARCH_x86)