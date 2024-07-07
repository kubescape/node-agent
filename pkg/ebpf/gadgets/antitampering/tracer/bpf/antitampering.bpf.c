#include "../../../../include/amd64/vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "../../../../include/mntns_filter.h"
#include "../../../../include/filesystem.h"
#include "../../../../include/macros.h"
#include "../../../../include/buffer.h"

#include "antitampering.h"

/*
    * This BPF program is a tampering detection mechanism for BPF maps.
    * It uses the bpf_map LSM hook to detect write operations on BPF maps.
    * It checks if the PID is in the allowed_pids map and the map name is in the restricted_maps_names map.
    * If the PID is not found in allowed_pids and the map name is found in restricted_maps_names, the write operation is denied and an event is emitted.
    * The event contains the timestamp, PID, PPID, UID, GID, process name, map name, executable path, and whether the process is in an overlayfs upper layer.
*/

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

// Allowed pids map.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 1024);
} allowed_pids SEC(".maps");

// Restricted maps names map.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u8);
    __uint(max_entries, 1024);
} restricted_maps_names SEC(".maps");

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

// Function to get the map name
static __always_inline const char* get_map_name(struct bpf_map *map) {
    const char *map_name;
    bpf_probe_read_kernel(&map_name, sizeof(map_name), &map->name);
    return map_name;
}

// static __always_inline int strcmp_ebpf(const char *s1, const char *s2) {
//     for (int i = 0; i < MAX_STRING_LEN; i++) {
//         char c1 = s1[i];
//         char c2 = s2[i];
        
//         if (c1 != c2) {
//             return c1 - c2;
//         }
//         if (c1 == '\0') {
//             break;
//         }
//     }
//     return 0;
// }

static __always_inline void submit_event(void *ctx, const char *map_name) {
    struct event *event;
    u32 zero = 0;
    event = bpf_map_lookup_elem(&empty_event, &zero);
    if (!event) {
        return;
    }

    struct task_struct *current_task = (struct task_struct*)bpf_get_current_task();
    if (!current_task) {
        return;
    }

    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = (u32)uid_gid;

    if (valid_uid(targ_uid) && targ_uid != uid) {
        return;
    }

    event->timestamp = bpf_ktime_get_boot_ns();
    event->mntns_id = BPF_CORE_READ(current_task, nsproxy, mnt_ns, ns.inum);
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->ppid = BPF_CORE_READ(current_task, real_parent, pid);
    event->uid = uid;
    event->gid = (u32)(uid_gid >> 32);
    event->upper_layer = has_upper_layer();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_kernel_str(event->map_name, MAX_STRING_SIZE, map_name);

    struct file *exe_file = BPF_CORE_READ(current_task, mm, exe_file);
    char *exepath;
    exepath = get_path_str(&exe_file->f_path);
    bpf_probe_read_kernel_str(event->exepath, MAX_STRING_SIZE, exepath);

    /* emit event */
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(struct event));
}

// // Iterate over all tasks and populate the allowed_pids map with the current PID of the "node-agent" process.
// SEC("iter/task")
// int iterate_over_tasks(struct bpf_iter__task *ctx) {
//     struct task_struct *task = ctx->task;
//     if (!task)
//         return 0; // Continue iteration if task is NULL

//     u32 pid = BPF_CORE_READ(task, pid);
//     char comm[TASK_COMM_LEN];
//     BPF_CORE_READ_STR_INTO(&comm, task, comm);

//     // Direct comparison using BPF_CORE_READ_STR_INTO result
//     if (strcmp_ebpf(comm, "node-agent") == 0) {
//         bpf_map_update_elem(&allowed_pids, &pid, &pid, BPF_ANY);
//     }

//     return 0;
// }

// LSM hook function for bpf_map.
SEC("lsm/bpf_map")
int trace_tampering(void *ctx, struct bpf_map *map, fmode_t fmode) {
    // Only check for write operations.
    if (fmode & FMODE_WRITE) {
        // Check if the PID is in the allowed_pids map and the map name is in the restricted_maps_names map.
        pid_t pid = bpf_get_current_pid_tgid() >> 32;
        u8 *value;
        value = bpf_map_lookup_elem(&allowed_pids, &pid);
        const char *map_name = get_map_name(map);

        if (!value && bpf_map_lookup_elem(&restricted_maps_names, map_name)) {
            // PID not found in allowed_pids and map name found in restricted_maps_names, deny write operation and audit.
            submit_event(ctx, map_name);
            return -EPERM;
        }
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
