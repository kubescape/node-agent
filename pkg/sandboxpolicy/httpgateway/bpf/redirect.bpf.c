// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Kubescape Authors

// Gateway redirect for the http section of a sandbox policy.
//
// Attached once at the cgroup root. A task is covered when its cgroup, or the
// nearest bound cgroup above it, has an entry in `bindings`. For a covered
// task:
//
//   cgroup/connect4, connect6  a TCP connection to port 443 whose destination
//       is in the binding's `ai_dsts` set is rewritten to the node's gateway
//       listener. The original destination is kept under the socket cookie.
//       A connection straight to the gateway listener is recorded too, with
//       no rewrite. UDP to port 443 and real IPv6 to port 443 are refused
//       (EPERM) for destinations in the same set, so clients fall back to
//       TCP over IPv4.
//   cgroup/sendmsg4, sendmsg6  the same refusal for unconnected UDP.
//   sockops                    when the connection is established the record
//       moves to `conns`, keyed by the socket's local address and port; it is
//       deleted when the socket closes.
//
// Nothing else is touched: another port, a destination outside the set, an
// exempt destination, an unbound task, or a binding whose gate is failing
// open all keep their own route.
//
// The layout of `bindings`, `ai_dsts`, `conns` and `exempt` is a contract with
// the readers of the pinned maps (layout.go). Integers are in host byte order;
// addresses are 16 bytes in network order, IPv4 in its IPv6-mapped form.

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define PORT_HTTPS bpf_htons(443)
#define V4_MAPPED bpf_htonl(0xffff)

// Cgroup levels checked for a bound cgroup above the task's own.
#define MAX_CGROUP_LEVELS 12

#define GATE_REDIRECTING 0
#define GATE_FAILING_OPEN 1
#define GATE_RECOVERING 2

struct binding {
	__u32 id;
	__u8 posture; // 0 allow, 1 deny
	__u8 gate;
	__u8 pad[2];
};

struct ai_key {
	__u32 binding;
	__u32 addr[4];
};

struct conn_key {
	__u8 addr[16];
	__u16 port; // host order
};

struct conn {
	__u64 cgroup;
	__u32 pid; // thread group id in the initial pid namespace
	__u32 binding;
	__u8 addr[16]; // original destination
	__u16 port; // host order
	__u8 pad[6];
};

struct exempt_key {
	__u32 prefixlen;
	__u32 addr[4];
};

struct config {
	__u32 gateway_ip4; // network order; 0: no gateway, nothing is redirected
	__u16 gateway_port; // network order
	__u16 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct binding);
} bindings SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct ai_key);
	__type(value, __u64); // expiry, bpf_ktime_get_ns clock; 0: no expiry
} ai_dsts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct conn_key);
	__type(value, struct conn);
} conns SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__type(key, struct exempt_key);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} exempt SEC(".maps");

// Connections between connect and establish, by socket cookie.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct conn);
} pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct config);
} cfg SEC(".maps");

enum {
	STAT_REDIRECTED,
	STAT_RECORDED_DIRECT,
	STAT_ESTABLISHED,
	STAT_CLOSED,
	STAT_QUIC_REFUSED,
	STAT_IPV6_REFUSED,
	STAT_EXEMPTED,
	STAT_GATE_OPEN,
	STAT_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

static __always_inline void bump(__u32 i)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &i);
	if (v)
		*v += 1;
}

// covering returns the binding of the task's own cgroup, or else of the
// nearest bound cgroup above it, and the id of that cgroup.
static __always_inline struct binding *covering(__u64 *cgroup)
{
	__u64 id = bpf_get_current_cgroup_id();
	struct binding *found = bpf_map_lookup_elem(&bindings, &id);
	struct binding *b;

	if (found) {
		*cgroup = id;
		return found;
	}
	for (int level = 1; level < MAX_CGROUP_LEVELS; level++) {
		id = bpf_get_current_ancestor_cgroup_id(level);
		if (!id)
			break;
		b = bpf_map_lookup_elem(&bindings, &id);
		if (b) {
			found = b;
			*cgroup = id;
		}
	}
	return found;
}

// in_ai_set reports whether addr is a live entry of the binding's set and is
// not exempt.
static __always_inline int in_ai_set(struct binding *b, const __u32 addr[4])
{
	struct exempt_key ek = { .prefixlen = 128 };
	struct ai_key ak = { .binding = b->id };
	__u64 *expiry;

	__builtin_memcpy(ek.addr, addr, sizeof(ek.addr));
	if (bpf_map_lookup_elem(&exempt, &ek)) {
		bump(STAT_EXEMPTED);
		return 0;
	}
	__builtin_memcpy(ak.addr, addr, sizeof(ak.addr));
	expiry = bpf_map_lookup_elem(&ai_dsts, &ak);
	if (!expiry)
		return 0;
	return *expiry == 0 || *expiry > bpf_ktime_get_ns();
}

static __always_inline void remember(void *ctx, struct binding *b, __u64 cgroup,
				     const __u32 addr[4], __u16 port_net)
{
	struct conn c = {};
	__u64 cookie = bpf_get_socket_cookie(ctx);

	c.cgroup = cgroup;
	c.pid = bpf_get_current_pid_tgid() >> 32;
	c.binding = b->id;
	__builtin_memcpy(c.addr, addr, sizeof(c.addr));
	c.port = bpf_ntohs(port_net);
	bpf_map_update_elem(&pending, &cookie, &c, BPF_ANY);
}

enum verdict {
	PASS, // leave the call alone
	REFUSE, // EPERM
	REDIRECT, // rewrite the destination to the gateway
};

// judge decides one connect or sendmsg to addr (IPv4 in its mapped form).
static __always_inline enum verdict judge(struct bpf_sock_addr *ctx,
					  const __u32 addr[4], struct config **cfgp)
{
	__u32 zero = 0;
	struct config *c = bpf_map_lookup_elem(&cfg, &zero);
	__u16 port = ctx->user_port;
	__u32 proto = ctx->protocol;
	int mapped = addr[0] == 0 && addr[1] == 0 && addr[2] == V4_MAPPED;
	int to_gateway = c && c->gateway_ip4 && mapped &&
			 addr[3] == c->gateway_ip4 && port == c->gateway_port;
	struct binding *b;
	__u64 cgroup = 0;

	*cfgp = c;
	if (port != PORT_HTTPS && !to_gateway)
		return PASS;
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return PASS;
	b = covering(&cgroup);
	if (!b)
		return PASS;
	if (to_gateway) {
		// Recorded, so every connection a bound pod makes to the gateway
		// has an identity the kernel observed.
		if (proto == IPPROTO_TCP) {
			remember(ctx, b, cgroup, addr, port);
			bump(STAT_RECORDED_DIRECT);
		}
		return PASS;
	}
	if (b->gate == GATE_FAILING_OPEN) {
		bump(STAT_GATE_OPEN);
		return PASS;
	}
	if (!in_ai_set(b, addr))
		return PASS;
	if (proto == IPPROTO_UDP) {
		bump(STAT_QUIC_REFUSED);
		return REFUSE;
	}
	if (!mapped) {
		bump(STAT_IPV6_REFUSED);
		return REFUSE;
	}
	if (!c || !c->gateway_ip4)
		return PASS;
	remember(ctx, b, cgroup, addr, port);
	bump(STAT_REDIRECTED);
	return REDIRECT;
}

SEC("cgroup/connect4")
int gw_connect4(struct bpf_sock_addr *ctx)
{
	__u32 addr[4] = { 0, 0, V4_MAPPED, ctx->user_ip4 };
	struct config *c;

	switch (judge(ctx, addr, &c)) {
	case REFUSE:
		return 0;
	case REDIRECT:
		ctx->user_ip4 = c->gateway_ip4;
		ctx->user_port = c->gateway_port;
	default:
		return 1;
	}
}

SEC("cgroup/connect6")
int gw_connect6(struct bpf_sock_addr *ctx)
{
	__u32 addr[4] = { ctx->user_ip6[0], ctx->user_ip6[1], ctx->user_ip6[2],
			  ctx->user_ip6[3] };
	struct config *c;

	switch (judge(ctx, addr, &c)) {
	case REFUSE:
		return 0;
	case REDIRECT:
		// judge redirects only an IPv4-mapped destination.
		ctx->user_ip6[3] = c->gateway_ip4;
		ctx->user_port = c->gateway_port;
	default:
		return 1;
	}
}

SEC("cgroup/sendmsg4")
int gw_sendmsg4(struct bpf_sock_addr *ctx)
{
	__u32 addr[4] = { 0, 0, V4_MAPPED, ctx->user_ip4 };
	struct config *c;

	return judge(ctx, addr, &c) != REFUSE;
}

SEC("cgroup/sendmsg6")
int gw_sendmsg6(struct bpf_sock_addr *ctx)
{
	__u32 addr[4] = { ctx->user_ip6[0], ctx->user_ip6[1], ctx->user_ip6[2],
			  ctx->user_ip6[3] };
	struct config *c;

	return judge(ctx, addr, &c) != REFUSE;
}

SEC("sockops")
int gw_sockops(struct bpf_sock_ops *skops)
{
	// Every field is loaded before any branch: the verifier refuses a
	// context access the compiler merged across branches.
	__u32 op = skops->op;
	__u32 family = skops->family;
	__u32 local4 = skops->local_ip4;
	__u32 w0 = skops->local_ip6[0];
	__u32 w1 = skops->local_ip6[1];
	__u32 w2 = skops->local_ip6[2];
	__u32 w3 = skops->local_ip6[3];
	__u32 port = skops->local_port; // host order
	__u32 state = skops->args[1];
	__u32 addr[4] = { 0, 0, V4_MAPPED, 0 };
	struct conn_key k = {};
	struct conn *c;
	__u64 cookie;

	asm volatile("" : "+r"(local4), "+r"(w3));
	if (op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB &&
	    !(op == BPF_SOCK_OPS_STATE_CB && state == BPF_TCP_CLOSE))
		return 1;
	if (family == AF_INET)
		addr[3] = local4;
	else if (family == AF_INET6 && w0 == 0 && w1 == 0 && w2 == V4_MAPPED)
		addr[3] = w3;
	else
		return 1;
	__builtin_memcpy(k.addr, addr, sizeof(k.addr));
	k.port = port;

	if (op == BPF_SOCK_OPS_STATE_CB) {
		bpf_map_delete_elem(&conns, &k);
		bump(STAT_CLOSED);
		return 1;
	}
	cookie = bpf_get_socket_cookie(skops);
	c = bpf_map_lookup_elem(&pending, &cookie);
	if (!c)
		return 1;
	bpf_map_update_elem(&conns, &k, c, BPF_ANY);
	bpf_map_delete_elem(&pending, &cookie);
	bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
	bump(STAT_ESTABLISHED);
	return 1;
}
