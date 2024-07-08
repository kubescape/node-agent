#pragma once

#include "../../../../include/types.h"

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif
#define INVALID_UID ((uid_t)-1)
// Defined in include/uapi/linux/magic.h
#define OVERLAYFS_SUPER_MAGIC 0x794c7630
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
// Defined in include/linux/fs.h
#ifndef FMODE_WRITE
#define FMODE_WRITE ((fmode_t)2)
#endif
// Defined in include/linux/errno.h
#ifndef EPERM
#define EPERM 1
#endif
// Define maximum string length
#define MAX_STRING_LEN 256
#define MAX_MAP_NAME_LEN 16

struct event {
    gadget_timestamp timestamp;
    gadget_mntns_id mntns_id;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
	bool upper_layer;
    __u8 comm[TASK_COMM_LEN];
    __u8 exepath[MAX_STRING_SIZE];
    __u8 map_name[MAX_MAP_NAME_LEN];
};
