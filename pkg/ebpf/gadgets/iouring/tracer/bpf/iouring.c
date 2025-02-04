#include "iouring.h"

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

#if HAS_KERNEL_FEATURE(6, 3)
SEC("tp/io_uring/io_uring_submit_req")
int handle_submit_req(struct trace_event_raw_io_uring_submit_req *ctx) {
#else
SEC("tp/io_uring/io_uring_submit_sqe") 
int handle_submit_req(struct trace_event_raw_io_uring_submit_sqe *ctx) {
#endif
    if (should_discard()) {
        return 0;
    }
    __u64 pid_tgid;
    u32 zero = 0;

    struct event *event = bpf_map_lookup_elem(&empty_event, &zero);
    if (!event)
        return 0;

    event->mntns_id = gadget_get_mntns_id();
    event->timestamp = bpf_ktime_get_boot_ns();
    
    pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->tid = pid_tgid & 0xFFFFFFFF;
    
    __u64 uid_gid = bpf_get_current_uid_gid();
    event->uid = uid_gid & 0xFFFFFFFF;
    event->gid = uid_gid >> 32;
    
    if (bpf_get_current_comm(&event->comm, sizeof(event->comm)) < 0)
        return 0;

    event->opcode = ctx->opcode;
    event->flags = ctx->flags;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(struct event));

    return 0;
}

char _license[] SEC("license") = "GPL";
