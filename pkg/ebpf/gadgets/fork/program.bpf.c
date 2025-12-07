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
#include "exe_path.h"

// events is the name of the buffer map and 1024 * 256 (256KB) is its size.
GADGET_TRACER_MAP(events, 1024 * 256);

// Define a tracer
GADGET_TRACER(fork, events, event);

SEC("raw_tracepoint/sched_process_fork")
int tracepoint__sched_fork(struct bpf_raw_tracepoint_args *ctx)
{
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

    // Mount namespace filtering based on the child.
    gadget_mntns_id mntns_id = BPF_CORE_READ(child, nsproxy, mnt_ns, ns.inum);
    if (gadget_should_discard_mntns_id(mntns_id)) {
        gadget_discard_buf(event);
        return 0;
    }

    // Get uid/gid from current context (parent doing the fork)
    // Child inherits these at fork time
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = (u32)uid_gid;
    u32 gid = (u32)(uid_gid >> 32);

    // Populate proc struct with CHILD's data (not using gadget_process_populate
    // which would incorrectly use the parent's context)
    event->proc.pid = BPF_CORE_READ(child, tgid);
    event->proc.tid = BPF_CORE_READ(child, pid);
    event->proc.mntns_id = mntns_id;
    event->proc.creds.uid = uid;
    event->proc.creds.gid = gid;

    // Get child's comm - at fork time, child inherits parent's comm
    bpf_get_current_comm(&event->proc.comm, sizeof(event->proc.comm));

    // Populate proc.parent with the PARENT's data (the process doing the fork)
    event->proc.parent.pid = BPF_CORE_READ(parent, tgid);
    BPF_CORE_READ_STR_INTO(&event->proc.parent.comm, parent, comm);

    // Parent/child identifiers
    event->proc.mntns_id = mntns_id;
    event->parent_pid = BPF_CORE_READ(parent, tgid);
    event->child_pid = BPF_CORE_READ(child, tgid);
    event->child_tid = BPF_CORE_READ(child, pid);

    // Executable path for the child
    read_task_exe_path(child, event->exepath, sizeof(event->exepath));

    event->timestamp_raw = bpf_ktime_get_boot_ns();

    gadget_submit_buf(ctx, &events, event, sizeof(*event));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
