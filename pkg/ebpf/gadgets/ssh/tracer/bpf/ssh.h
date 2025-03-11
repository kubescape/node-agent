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
#define SSH_SIGNATURE "SSH-"
#define SSH_SIG_LEN 4
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_HLEN	14

struct event {
    // Keep netns at the top: networktracer depends on it
    __u32 netns;
    
    gadget_timestamp timestamp;
    gadget_mntns_id mntns_id;
    __u32 pid;
    __u32 uid;
    __u32 gid;
    __u16 dst_port;
    __u16 src_port;
    __u32 dst_ip;
    __u32 src_ip;
    __u8 comm[TASK_COMM_LEN];
};
