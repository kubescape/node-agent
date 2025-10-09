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

// events is the name of the buffer map and 1024 * 256 (256KB) is its size.
GADGET_TRACER_MAP(events, 1024 * 256);

// Define a tracer
GADGET_TRACER(exit, events, event);

// This gadget is used to trace the sched_process_exit tracepoint.
SEC("raw_tracepoint/sched_process_exit")
int tracepoint__sched_exit(struct bpf_raw_tracepoint_args *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }
    
    struct event *event;
    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event) {
        return 0;
    }

    struct task_struct *task = (struct task_struct *) ctx->args[0];
    if (!task) {
        gadget_discard_buf(event);
        return 0;
    }

    // Check mount namespace filtering
    gadget_mntns_id mntns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
    if (gadget_should_discard_mntns_id(mntns_id)) {
        gadget_discard_buf(event);
        return 0;
    }

    // Populate the process data into the event.
    gadget_process_populate(&event->process);

    // Exit info
    event->exit_code = BPF_CORE_READ(task, exit_code);
    event->exit_signal = BPF_CORE_READ(task, exit_signal);
    event->upper_layer = has_upper_layer();

    /* emit event */
    gadget_submit_buf(ctx, &events, event, sizeof(*event));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

