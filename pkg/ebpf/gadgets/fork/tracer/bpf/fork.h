#pragma once

#include "../../../../include/types.h"

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif
#define INVALID_UID ((uid_t)-1)
// Defined in include/uapi/linux/magic.h
#define OVERLAYFS_SUPER_MAGIC 0x794c7630
#ifndef PATH_MAX
#define PATH_MAX 512
#endif

// Note: the path should always be in the bottom of the struct to avoid trimming of data.
struct event {
    gadget_timestamp timestamp;
    gadget_mntns_id mntns_id;
    __u32 pid;
    __u32 tid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
	bool upper_layer;
    __u8 comm[TASK_COMM_LEN];
    __u8 exepath[MAX_STRING_SIZE];
    __u32 child_pid;
    __u32 child_tid;
}; 