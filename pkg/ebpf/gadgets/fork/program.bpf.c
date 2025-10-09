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
#include "exe_path.h"

// events is the name of the buffer map and 1024 * 256 (256KB) is its size.
GADGET_TRACER_MAP(events, 1024 * 256);

// Define a tracer
GADGET_TRACER(fork, events, event);

SEC("raw_tracepoint/sched_process_fork")
int tracepoint__sched_fork(struct bpf_raw_tracepoint_args *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }

    struct event *event;
    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event) {
        return 0;
    }

    struct task_struct *parent = (struct task_struct *) ctx->args[0];
    struct task_struct *child = (struct task_struct *) ctx->args[1];
    if (!parent || !child) {
        gadget_discard_buf(event);
        return 0;
    }

    // Populate the process data into the event with the child context.
    gadget_process_populate(&event->process);

    // Mount namespace filtering based on the child.
    gadget_mntns_id mntns_id = BPF_CORE_READ(child, nsproxy, mnt_ns, ns.inum);
    if (gadget_should_discard_mntns_id(mntns_id)) {
        gadget_discard_buf(event);
        return 0;
    }

    // Parent/child identifiers
    event->parent_pid = BPF_CORE_READ(parent, tgid);
    event->child_pid = BPF_CORE_READ(child, tgid);
    event->child_tid = BPF_CORE_READ(child, pid);

    // Executable path for the child
    read_task_exe_path(child, event->exepath, sizeof(event->exepath));

    gadget_submit_buf(ctx, &events, event, sizeof(*event));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

