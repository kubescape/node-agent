#pragma once

#define NETWORK_PATH_MAX 256

#define PACKET_HOST 0
#define PACKET_OUTGOING 4

#define NETWORK_CONNECT_OWNERS_MAX 8192

// Full 4-tuple of an outgoing TCP connection, as seen on its SYN.
// Addresses are in network byte order; IPv4 uses the first 4 bytes.
// Ports are in host byte order.
struct connect_key {
	__u32 netns;
	__u16 lport;
	__u16 rport;
	__u8 laddr[16];
	__u8 raddr[16];
	__u8 version; // 4 or 6, as the packet carries it
	__u8 pad[3];
};

// The task that called connect() for a connect_key.
struct connect_owner {
	__u64 mntns;
	__u64 pid_tgid;
	__u64 uid_gid;
	__u32 ppid;
	__u32 ptid;
	char task[TASK_COMM_LEN];
	char ptask[TASK_COMM_LEN];
	char exepath[NETWORK_PATH_MAX];
};

struct event_t {
	gadget_timestamp timestamp_raw;
	gadget_netns_id netns_id;
	struct gadget_l4endpoint_t endpoint;
	struct gadget_process proc;
	__u8 egress;
	char exepath[NETWORK_PATH_MAX];
};
