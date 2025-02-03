#include "../../../../include/amd64/vmlinux.h"
#include "../../../../include/types.h"
#include <bpf/bpf_helpers.h>
#include "../../../../include/mntns_filter.h"
#include "../../../../include/filesystem.h"
#include "../../../../include/macros.h"
#include "../../../../include/buffer.h"


struct event {
    gadget_timestamp timestamp;
    gadget_mntns_id mntns_id;
    __u32 opcode;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    char comm[16];
    __u32 flags;
    __u64 user_data;
};
