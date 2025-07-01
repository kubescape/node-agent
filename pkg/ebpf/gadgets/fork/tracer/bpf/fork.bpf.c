#include "../../../../include/amd64/vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "../../../../include/mntns_filter.h"
#include "../../../../include/filesystem.h"
#include "../../../../include/macros.h"
#include "../../../../include/buffer.h"

#include "fork.h"

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

static __always_inline int get_task_ns_tgid(struct task_struct *task)
{
    if (!task) {
        return 0;
    }
    return BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
}

static __always_inline int get_task_ns_pid(struct task_struct *task)
{
    if (!task) {
        return 0;
    }
    return BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
}

static __always_inline struct task_struct *get_parent_task(struct task_struct *task)
{
    if (!task) {
        return NULL;
    }
    return BPF_CORE_READ(task, real_parent);
}

static __always_inline struct task_struct *get_leader_task(struct task_struct *task)
{
    if (!task) {
        return NULL;
    }
    return BPF_CORE_READ(task, group_leader);
}

static __always_inline u64 get_current_time_in_ns()
{
    return bpf_ktime_get_boot_ns();
}

// This gadget is used to trace the sched_process_fork tracepoint.
SEC("raw_tracepoint/sched_process_fork")
int tracepoint__sched_fork(struct bpf_raw_tracepoint_args *ctx)
{
    struct event *event;
    u32 zero = 0;
    event = bpf_map_lookup_elem(&empty_event, &zero);
    if (!event) {
        return 0;
    }

    struct task_struct *parent = (struct task_struct *) ctx->args[0];
    struct task_struct *child = (struct task_struct *) ctx->args[1];
    
    if (!parent || !child) {
        return 0;
    }

    struct task_struct *leader = get_leader_task(child);
    struct task_struct *parent_process = get_leader_task(get_parent_task(leader));

    // Check mount namespace filtering
    u64 mntns_id = BPF_CORE_READ(child, nsproxy, mnt_ns, ns.inum);
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

    // Get parent and child information
    int parent_pid = BPF_CORE_READ(parent, tgid);
    int child_pid = BPF_CORE_READ(child, tgid);
    int child_tid = BPF_CORE_READ(child, pid);

    // Populate the event structure
    event->timestamp = timestamp;
    event->mntns_id = mntns_id;
    event->pid = child_pid;
    event->tid = child_tid;
    event->ppid = parent_pid;
    event->uid = uid;
    event->gid = (u32)(uid_gid >> 32);
    event->upper_layer = has_upper_layer();
    event->child_pid = child_pid;
    event->child_tid = child_tid;
    
    // Get command name
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Get executable path
    struct file *exe_file = BPF_CORE_READ(child, mm, exe_file);
    if (exe_file) {
        char *exepath = get_path_str(&exe_file->f_path);
        bpf_probe_read_kernel_str(event->exepath, MAX_STRING_SIZE, exepath);
    }

    /* emit event */
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(struct event));

    return 0;
}

char _license[] SEC("license") = "GPL"; 