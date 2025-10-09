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

// events is the name of the buffer map and 1024 * 256 (256KB) is its size.
GADGET_TRACER_MAP(events, 1024 * 256);

// Define a tracer
GADGET_TRACER(iouring, events, event);

// Use the modern tracepoint: io_uring_submit_req (>= 6.3)
SEC("tp/io_uring/io_uring_submit_req")
int handle_submit_req(struct trace_event_raw_io_uring_submit_req *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }

    struct event *event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event)
        return 0;

    gadget_process_populate(&event->process);
    event->opcode = ctx->opcode;
    event->flags = ctx->flags;

    gadget_submit_buf(ctx, &events, event, sizeof(*event));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
