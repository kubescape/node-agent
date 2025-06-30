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

// This gadget is used to trace the sched_fork tracepoint.
SEC("tracepoint/sched/sched_fork")
int tracepoint__sched_fork(void *ctx)
{
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

    u64 mntns_id = BPF_CORE_READ(current_task, nsproxy, mnt_ns, ns.inum);
    if (gadget_should_discard_mntns_id(mntns_id)) {
        return 0;
    }

    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = (u32)uid_gid;

    if (valid_uid(targ_uid) && targ_uid != uid) {
        return 0;
    }

    // For sched_fork, we can get the child PID from the current task's children
    // or use a different approach. For now, let's set child_pid to 0
    // and handle it in userspace if needed
    u32 child_pid = 0;
    u32 child_tid = 0;

    event->timestamp = bpf_ktime_get_boot_ns();
    event->mntns_id = mntns_id;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->ppid = BPF_CORE_READ(current_task, real_parent, pid);
    event->uid = uid;
    event->gid = (u32)(uid_gid >> 32);
    event->upper_layer = has_upper_layer();
    event->child_pid = child_pid;
    event->child_tid = child_tid;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    struct file *exe_file = BPF_CORE_READ(current_task, mm, exe_file);
    char *exepath;
    exepath = get_path_str(&exe_file->f_path);
    bpf_probe_read_kernel_str(event->exepath, MAX_STRING_SIZE, exepath);

    /* emit event */
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(struct event));

    return 0;
}

char _license[] SEC("license") = "GPL"; 