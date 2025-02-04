#include "../../../../include/amd64/vmlinux.h"
#include "../../../../include/types.h"
#include <bpf/bpf_helpers.h>
#include "../../../../include/mntns_filter.h"
#include "../../../../include/filesystem.h"
#include "../../../../include/macros.h"
#include "../../../../include/buffer.h"

extern int LINUX_KERNEL_VERSION __kconfig;

#define HAS_KERNEL_FEATURE(maj, min) (CURRENT_KERNEL_VERSION >= KERNEL_VERSION(maj, min, 0))

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
    gadget_timestamp timestamp;
    gadget_mntns_id mntns_id;
    __u32 opcode;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u32 flags;
    __u64 user_data;
    __u8 comm[16];
};
