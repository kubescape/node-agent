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
#include "upper_layer.h"
#include "exe_path.h"

// events is the name of the buffer map and 1024 * 256 (256KB) is its size.
GADGET_TRACER_MAP(events, 1024 * 256);

// Define a tracer
GADGET_TRACER(hardlink, events, event);

SEC("tracepoint/syscalls/sys_enter_link")
int enter_link(struct syscall_trace_enter *ctx)
{
    // if (gadget_should_discard_data_current()) {
    //     return 0;
    // }

    struct event *event;
    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event) {
        return 0;
    }

    // Populate the process data into the event.
    gadget_process_populate(&event->proc);

    // Validate the oldpath and newpath.
    if ((void *)ctx->args[0] == NULL || (void *)ctx->args[1] == NULL) {
        gadget_discard_buf(event);
        return 0;
    }

    size_t oldpath_len = 0;
    size_t newpath_len = 0;

    oldpath_len = bpf_probe_read_user_str(&event->oldpath, sizeof(event->oldpath), (void *)ctx->args[0]);
    if(oldpath_len <= 0) {
        gadget_discard_buf(event);
        return 0;
    }

    newpath_len = bpf_probe_read_user_str(&event->newpath, sizeof(event->newpath), (void *)ctx->args[1]);
    if(newpath_len <= 0) {
        gadget_discard_buf(event);
        return 0;
    }

    event->upper_layer = has_upper_layer();
    read_exe_path(event->exepath, sizeof(event->exepath));

    event->timestamp_raw = bpf_ktime_get_boot_ns();

    gadget_submit_buf(ctx, &events, event, sizeof(*event));

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_linkat")
int enter_linkat(struct syscall_trace_enter *ctx)
{
    // if (gadget_should_discard_data_current()) {
    //     return 0;
    // }

    struct event *event;
    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event) {
        return 0;
    }

    // Populate the process data into the event.
    gadget_process_populate(&event->proc);

    // Validate the oldpath and newpath (args[1] and args[3]).
    if ((void *)ctx->args[1] == NULL || (void *)ctx->args[3] == NULL) {
        gadget_discard_buf(event);
        return 0;
    }

    size_t oldpath_len = 0;
    size_t newpath_len = 0;

    oldpath_len = bpf_probe_read_user_str(&event->oldpath, sizeof(event->oldpath), (void *)ctx->args[1]);
    if(oldpath_len <= 0) {
        gadget_discard_buf(event);
        return 0;
    }

    newpath_len = bpf_probe_read_user_str(&event->newpath, sizeof(event->newpath), (void *)ctx->args[3]);
    if(newpath_len <= 0) {
        gadget_discard_buf(event);
        return 0;
    }

    event->upper_layer = has_upper_layer();
    read_exe_path(event->exepath, sizeof(event->exepath));

    event->timestamp_raw = bpf_ktime_get_boot_ns();

    gadget_submit_buf(ctx, &events, event, sizeof(*event));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
