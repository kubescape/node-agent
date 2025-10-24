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

// Inspektor Gadget filesystem
#include <gadget/filesystem.h>

#include "program.h"
#include "exe_path.h"
#include "upper_layer.h"

// events is the name of the buffer map and 1024 * 256 (256KB) is its size.
GADGET_TRACER_MAP(events, 1024 * 256);

// Define a tracer
GADGET_TRACER(unshare, events, event);

SEC("tracepoint/syscalls/sys_enter_unshare")
int trace_enter_unshare(struct trace_event_raw_sys_enter *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }

    struct event *event;
    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event) {
        return 0;
    }

    // Populate the process data into the event.
    gadget_process_populate(&event->proc);

    // For unshare, the flags are passed as the first argument
    event->flags = (uint64_t)ctx->args[0];

    // Read executable path
    read_exe_path(event->exepath, sizeof(event->exepath));

    // Check if running in upper layer
    event->upper_layer = has_upper_layer();

    gadget_submit_buf(ctx, &events, event, sizeof(*event));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
