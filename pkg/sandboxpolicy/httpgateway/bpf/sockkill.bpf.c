// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Kubescape Authors

// Socket kill for a bound pod: a TCP socket iterator that destroys the pod's
// connections to port 443 of an address in its binding's `ai_dsts` set that
// did not go through the gateway (no `conns` entry for the socket's local
// address and port). The application reconnects, and the new connection is
// redirected.
//
// The iterator walks the network namespace of the task that opens it, so the
// loader opens it inside the pod's network namespace. It needs
// bpf_sock_destroy (Linux 6.5); it is a separate object so that the redirect
// loads on older kernels.

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define AF_INET 2
#define AF_INET6 10
#define V4_MAPPED bpf_htonl(0xffff)

// Socket states that are not a connection an application still holds. The
// iterator visits these too: a TIME_WAIT entry stays for a minute after its
// connection closed.
#define TCP_TIME_WAIT 6
#define TCP_CLOSE 7
#define TCP_LISTEN 10
#define TCP_NEW_SYN_RECV 12

// The kernel types, with only the fields read here (CO-RE).
struct sock_common {
	__be32 skc_daddr;
	__be32 skc_rcv_saddr;
	__be16 skc_dport;
	__u16 skc_num;
	unsigned short skc_family;
	volatile unsigned char skc_state;
} __attribute__((preserve_access_index));

struct bpf_iter__tcp {
	void *meta;
	struct sock_common *sk_common;
} __attribute__((preserve_access_index));

extern int bpf_sock_destroy(struct sock_common *sk) __ksym;

struct ai_key {
	__u32 binding;
	__u32 addr[4];
};

struct conn_key {
	__u8 addr[16];
	__u16 port;
};

// Shared with the redirect object: the loader passes its maps in.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct ai_key);
	__type(value, __u64);
} ai_dsts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__uint(key_size, sizeof(struct conn_key));
	__uint(value_size, 40);
} conns SEC(".maps");

const volatile __u32 binding_id;
__u64 seen;
__u64 destroyed;

SEC("iter/tcp")
int gw_kill(struct bpf_iter__tcp *ctx)
{
	struct sock_common *sk = ctx->sk_common;
	struct ai_key ak = { .binding = binding_id };
	struct conn_key ck = {};
	__u32 local[4] = { 0, 0, V4_MAPPED, 0 };
	__u64 *expiry;
	__u8 state;

	if (!sk)
		return 0;
	seen += 1;
	// An IPv4-mapped connection on an IPv6 socket has its IPv4 addresses in
	// the same fields. Real IPv6 to an AI address is refused at connect.
	if (sk->skc_family != AF_INET && sk->skc_family != AF_INET6)
		return 0;
	if (sk->skc_dport != bpf_htons(443))
		return 0;
	state = sk->skc_state;
	if (state == TCP_TIME_WAIT || state == TCP_CLOSE || state == TCP_LISTEN ||
	    state == TCP_NEW_SYN_RECV)
		return 0;
	ak.addr[2] = V4_MAPPED;
	ak.addr[3] = sk->skc_daddr;
	expiry = bpf_map_lookup_elem(&ai_dsts, &ak);
	if (!expiry)
		return 0;
	local[3] = sk->skc_rcv_saddr;
	__builtin_memcpy(ck.addr, local, sizeof(ck.addr));
	ck.port = sk->skc_num;
	if (bpf_map_lookup_elem(&conns, &ck))
		return 0;
	if (bpf_sock_destroy(sk) == 0)
		destroyed += 1;
	return 0;
}
