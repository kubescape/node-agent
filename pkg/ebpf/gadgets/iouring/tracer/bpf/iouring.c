#include "iouring.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 1024);
} events SEC(".maps");

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

SEC("tracepoint/io_uring/io_uring_submit_sqe")
int trace_io_uring_submit(struct trace_event_raw_io_uring_submit_sqe *ctx)
{
    if (should_discard()) {
        return 0;
    }

    struct event event = {};
    __u64 pid_tgid;

    event.mntns_id = gadget_get_mntns_id();
    event.timestamp = bpf_ktime_get_boot_ns();
    
    pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.tid = pid_tgid & 0xFFFFFFFF;
    
    __u64 uid_gid = bpf_get_current_uid_gid();
    event.uid = uid_gid & 0xFFFFFFFF;
    event.gid = uid_gid >> 32;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.opcode = ctx->opcode;
    event.flags = ctx->flags;
    event.user_data = ctx->user_data;
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";