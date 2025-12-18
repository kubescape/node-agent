// Kernel types definitions
#include <vmlinux.h>

// eBPF helpers signatures
// Check https://man7.org/linux/man-pages/man7/bpf-helpers.7.html to learn
// more about different available helpers
#include <bpf/bpf_helpers.h>

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

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");
 
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct event);
} empty_event SEC(".maps");

// Declared to avoid compiler deletion
const struct event *unusedevent __attribute__((unused));

static __always_inline int should_discard()
{
    u64 mntns_id;
    mntns_id = gadget_get_mntns_id();

    if (gadget_should_discard_mntns_id(mntns_id))
    {
        return 1;   
    }

    return 0;
}

// Define a tracer
GADGET_TRACER(iouring, events, event);

struct trace_event_raw_io_uring_submit_sqe {
	struct trace_entry ent;
	void *ctx;
	void *req;
	long long unsigned int user_data;
	u8 opcode;
	u32 flags;
	bool force_nonblock;
	bool sq_thread;
	char __data[0];
};

SEC("tp/io_uring/io_uring_submit_sqe")
int handle_submit_sqe(struct trace_event_raw_io_uring_submit_sqe *ctx)
{
    if (should_discard()) {
        return 0;
    }

    u32 zero = 0;
    struct event *event = bpf_map_lookup_elem(&empty_event, &zero);
    if (!event)
        return 0;

    // Populate the process data into the event.
    gadget_process_populate(&event->proc);

    event->opcode = ctx->opcode;
    event->flags = ctx->flags;

    // Populate the timestamp into the event.
    event->timestamp_raw = bpf_ktime_get_boot_ns();

    // Submit the event to the buffer.
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(struct event));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
