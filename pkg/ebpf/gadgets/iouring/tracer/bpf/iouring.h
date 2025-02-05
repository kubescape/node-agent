#include "../../../../include/amd64/vmlinux.h"
#include "../../../../include/types.h"
#include <bpf/bpf_helpers.h>
#include "../../../../include/mntns_filter.h"
#include "../../../../include/filesystem.h"
#include "../../../../include/macros.h"
#include "../../../../include/buffer.h"

#ifndef __KERNEL_FEATURE_H
#define __KERNEL_FEATURE_H

/* Define macro to check kernel version features */
#define HAS_KERNEL_FEATURE(major, minor) \
    (KERNEL_VERSION_MAJOR > (major) || \
    (KERNEL_VERSION_MAJOR == (major) && KERNEL_VERSION_MINOR >= (minor)))

/* Define current kernel version based on compile-time flags */
#ifdef VERSION_63
#define KERNEL_VERSION_MAJOR 6
#define KERNEL_VERSION_MINOR 3
#else
#define KERNEL_VERSION_MAJOR 0
#define KERNEL_VERSION_MINOR 0
#endif

#endif /* __KERNEL_FEATURE_H */

struct trace_event_raw_io_uring_submit_req {
    struct trace_entry ent;
    void *ctx;
    void *req;
    long long unsigned int user_data;
    u8 opcode;
    u32 flags;
    bool sq_thread;
    u32 __data_loc_op_str;
    char __data[0];
} __attribute__((preserve_access_index));

struct event {
    gadget_timestamp timestamp;  // Keep first
    gadget_mntns_id mntns_id;   // Keep second
    __u32 pid;
    __u32 tid; 
    __u32 uid;
    __u32 gid;
    __u32 opcode;
    __u32 flags;
    __u8 comm[16];             // Keep array at end
};

