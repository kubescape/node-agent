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

// events is the name of the buffer map and 1024 * 256 (256KB) is its size.
GADGET_TRACER_MAP(events, 1024 * 256);

// Define a tracer
GADGET_TRACER(exit, events, event);

// This gadget is used to trace the sched_process_exit tracepoint.
SEC("raw_tracepoint/sched_process_exit")
int tracepoint__sched_exit(struct bpf_raw_tracepoint_args *ctx)
{
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
    // gadget_process_populate(&event->proc);
    event->proc.pid = BPF_CORE_READ(task, tgid);
    event->proc.tid = BPF_CORE_READ(task, pid);
    event->proc.parent.pid = BPF_CORE_READ(task, real_parent, tgid);
    // event->proc.creds.uid = BPF_CORE_READ(task, real_cred, uid);
    // event->proc.creds.gid = BPF_CORE_READ(task, real_cred, gid);
    // event->proc.comm = BPF_CORE_READ(task, comm);
    // event->proc.parent.comm = BPF_CORE_READ(task, real_parent, comm);

    // Exit info
    event->proc.mntns_id = mntns_id;
    event->timestamp_raw = bpf_ktime_get_boot_ns();
    event->exit_code = BPF_CORE_READ(task, exit_code);
    event->exit_signal = BPF_CORE_READ(task, exit_signal);
    event->exit_pid = BPF_CORE_READ(task, tgid);
    event->exit_tid = BPF_CORE_READ(task, pid);
    event->exit_ppid = BPF_CORE_READ(task, real_parent, tgid);
    event->upper_layer = has_upper_layer();

    /* emit event */
    gadget_submit_buf(ctx, &events, event, sizeof(*event));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
