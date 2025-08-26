#include "../../../../include/amd64/vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "../../../../include/mntns_filter.h"
#include "../../../../include/filesystem.h"
#include "../../../../include/macros.h"
#include "../../../../include/buffer.h"

#include "exit.h"

// Events map.
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// Empty event map.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct event);
} empty_event SEC(".maps");

// we need this to make sure the compiler doesn't remove our struct.
const struct event *unusedevent __attribute__((unused));

static __always_inline u64 get_current_time_in_ns()
{
    return bpf_ktime_get_boot_ns();
}

// This gadget is used to trace the sched_process_exit tracepoint.
SEC("raw_tracepoint/sched_process_exit")
int tracepoint__sched_exit(struct bpf_raw_tracepoint_args *ctx)
{
    struct event *event;
    u32 zero = 0;
    event = bpf_map_lookup_elem(&empty_event, &zero);
    if (!event) {
        return 0;
    }

    struct task_struct *task = (struct task_struct *) ctx->args[0];
    
    if (!task) {
        return 0;
    }

    // Check mount namespace filtering
    u64 mntns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
    if (gadget_should_discard_mntns_id(mntns_id)) {
        return 0;
    }

    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = (u32)uid_gid;


    // The event timestamp, so process tree info can be changelog'ed.
    u64 timestamp = get_current_time_in_ns();

    // Get process information
    int pid = BPF_CORE_READ(task, tgid);
    int tid = BPF_CORE_READ(task, pid);
    int ppid = BPF_CORE_READ(task, real_parent, tgid);

    // Get exit information
    int exit_code = BPF_CORE_READ(task, exit_code);
    int exit_signal = BPF_CORE_READ(task, exit_signal);

    // Populate the event structure
    event->timestamp = timestamp;
    event->mntns_id = mntns_id;
    event->pid = pid;
    event->tid = tid;
    event->ppid = ppid;
    event->uid = uid;
    event->gid = (u32)(uid_gid >> 32);
    event->exit_code = exit_code;
    event->exit_signal = exit_signal;

    /* emit event */
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(struct event));

    return 0;
}

char _license[] SEC("license") = "GPL"; 