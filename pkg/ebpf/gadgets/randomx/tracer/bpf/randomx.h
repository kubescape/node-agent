#pragma once

#include "../../../../include/types.h"

// Utilize the kernel version provided by libbpf. (kconfig must be present).
extern int LINUX_KERNEL_VERSION __kconfig;

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif
#define INVALID_UID ((uid_t)-1)
// Defined in include/uapi/linux/magic.h
#define OVERLAYFS_SUPER_MAGIC 0x794c7630

#if LINUX_KERNEL_VERSION <= KERNEL_VERSION(5, 15, 0)
struct old_fpu {
	unsigned int last_cpu;
	unsigned char initialized;
	long: 24;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	union fpregs_state state;
};
#endif

struct event {
    gadget_timestamp timestamp;
    gadget_mntns_id mntns_id;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
	bool upper_layer;
    __u8 comm[TASK_COMM_LEN];
};
