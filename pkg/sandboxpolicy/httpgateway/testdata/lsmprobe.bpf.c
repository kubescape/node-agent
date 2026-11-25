// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Kubescape Authors

// Test probe for the hook order: a BPF LSM socket_connect program that records
// the IPv4 destination it is shown for one cgroup, and can deny one address.
// It stands in for the network section's LSM program, which decides on the
// same hook.

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct sockaddr_in4 {
	__u16 family;
	__u16 port; // network order
	__u32 addr; // network order
};

volatile __u64 watch_cgroup;
volatile __u32 deny_addr; // network order; 0: deny nothing
volatile __u32 seen_addr;
volatile __u16 seen_port;
volatile __u64 calls;

SEC("lsm/socket_connect")
int probe_connect(unsigned long long *ctx)
{
	void *address = (void *)ctx[1];
	int ret = (int)ctx[3];
	struct sockaddr_in4 sa = {};

	if (ret)
		return ret;
	if (bpf_get_current_cgroup_id() != watch_cgroup)
		return 0;
	if (bpf_probe_read_kernel(&sa, sizeof(sa), address))
		return 0;
	if (sa.family != 2)
		return 0;
	seen_addr = sa.addr;
	seen_port = sa.port;
	calls += 1;
	if (deny_addr && sa.addr == deny_addr)
		return -1; // EPERM
	return 0;
}
