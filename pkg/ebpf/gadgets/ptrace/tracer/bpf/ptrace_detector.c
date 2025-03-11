#include "ptrace_detector.h"

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

static __always_inline char * get_exe_path(struct task_struct* current_task ) {
        struct file *exe_file = BPF_CORE_READ(current_task, mm, exe_file);
        char *exepath;
        exepath = get_path_str(&exe_file->f_path);
        return exepath;
}


static __always_inline void populate_event(struct event* event) {
    u64 mntns_id = gadget_get_mntns_id();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;

    u64 uid_gid = bpf_get_current_uid_gid();
    event->uid = uid_gid & 0xFFFFFFFF;
    event->gid = uid_gid >> 32;
    event->timestamp = bpf_ktime_get_boot_ns();
    event->mntns_id = mntns_id;
    bpf_get_current_comm(&event->comm, sizeof(event->comm)); 
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_enter_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    long request = (long)ctx->args[0];
    
    if (should_discard()) {
        return 0;
    }

    struct event *event;
    u32 zero = 0;
    event = bpf_map_lookup_elem(&empty_event, &zero);
    if (!event) {
        return 0;
    }

    struct task_struct *current_task = (struct task_struct*)bpf_get_current_task();
    if (!current_task) {
        return 0;
    }

    if (request == PTRACE_SETREGS || request == PTRACE_POKETEXT || request == PTRACE_POKEDATA) {
            char* exepath = get_exe_path(current_task);   
            bpf_probe_read_kernel_str(event->exepath, MAX_STRING_SIZE, exepath);
            event->ppid = BPF_CORE_READ(current_task, real_parent, pid);
            event->request = request;
            populate_event(event);
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(struct event));
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
