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

const volatile uid_t targ_uid = INVALID_UID;

static __always_inline bool valid_uid(uid_t uid)
{
    return uid != INVALID_UID;
}

static __always_inline bool has_upper_layer()
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct inode *inode = BPF_CORE_READ(task, mm, exe_file, f_inode);
    if (!inode) {
        return false;
    }
    unsigned long sb_magic = BPF_CORE_READ(inode, i_sb, s_magic);

    if (sb_magic != OVERLAYFS_SUPER_MAGIC) {
        return false;
    }

    struct dentry *upperdentry;

    // struct ovl_inode defined in fs/overlayfs/ovl_entry.h
    // Unfortunately, not exported to vmlinux.h
    // and not available in /sys/kernel/btf/vmlinux
    // See https://github.com/cilium/ebpf/pull/1300
    // We only rely on vfs_inode and __upperdentry relative positions
    bpf_probe_read_kernel(&upperdentry, sizeof(upperdentry),
                  ((void *)inode) +
                      bpf_core_type_size(struct inode));
    return upperdentry != NULL;
}

// Helper functions to get task information
static __always_inline u64 get_task_start_time(struct task_struct *task)
{
    if (!task) {
        return 0;
    }
    return BPF_CORE_READ(task, start_time);
}

static __always_inline int get_task_host_tgid(struct task_struct *task)
{
    if (!task) {
        return 0;
    }
    return BPF_CORE_READ(task, tgid);
}

static __always_inline int get_task_host_pid(struct task_struct *task)
{
    if (!task) {
        return 0;
    }
    return BPF_CORE_READ(task, pid);
}

static __always_inline struct task_struct *get_parent_task(struct task_struct *task)
{
    if (!task) {
        return NULL;
    }
    return BPF_CORE_READ(task, real_parent);
}

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

    if (valid_uid(targ_uid) && targ_uid != uid) {
        return 0;
    }

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
    event->upper_layer = has_upper_layer();
    event->exit_code = exit_code;
    event->exit_signal = exit_signal;
    
    // Get command name
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Get executable path
    struct file *exe_file = BPF_CORE_READ(task, mm, exe_file);
    if (exe_file) {
        char *exepath = get_path_str(&exe_file->f_path);
        bpf_probe_read_kernel_str(event->exepath, MAX_STRING_SIZE, exepath);
    }

    /* emit event */
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(struct event));

    return 0;
}

char _license[] SEC("license") = "GPL"; 