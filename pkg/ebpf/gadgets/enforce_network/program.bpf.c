// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Kubescape Authors

// enforce_network: enforce an egress network policy (CIDRs, ports, protocol)
// for a set of containers with BPF LSM programs (socket_connect and
// socket_sendmsg). The decision and the maps are in network_policy.h.
//
// Notes:
// - Every task in a bound cgroup is judged; there is no arming. Container
//   runtimes make no inet connect or addressed send inside the container
//   cgroup before the workload runs.
// - The address is parsed by its sa_family, not by the socket family: an
//   AF_INET6 UDP socket accepts a sockaddr_in, and an AF_INET socket sends to
//   a sockaddr_in whose family is AF_UNSPEC.
// - A deny returns -EPERM before the connect or send happens.

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/macros.h>
#include <gadget/types.h>

// A subtree binding (a parent cgroup of containers) covers its descendant
// cgroups. Container bindings are exact.
#define BINDINGS_CGROUP_DEPTH 32

#include "../common/bindings.h"
#include "../common/verdict.h"
#include "network_policy.h"

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1
#define AF_UNSPEC 0
#define AF_INET 2
#define AF_INET6 10
#define NET_SOCK_RAW 3
#define NET_IPPROTO_L2TP 115
#define NET_TCP_CLOSE 7
#define NET_MSG_FASTOPEN 0x20000000

enum net_hook : __u32 {
	NET_HOOK_SOCKET_CONNECT,
	NET_HOOK_SOCKET_SENDMSG,
	// An operational fault: a bound slot with no policy, or a task outside
	// a Strict exact scope (dst is empty).
	NET_HOOK_FAULT,
};

struct event {
	VERDICT_BASE_FIELDS;
	__u32 host_pid;
	// Rule and origin ids of the deciding rule or default.
	__u32 rule_id;
	__u32 origin_id;
	// 1 when a default decided, not a rule.
	__u32 is_default;
	// Policy slot (combination of policies) of the bound container.
	__u32 slot;
	char comm[16];
	enum net_hook hook_raw;
	// Destination; an IPv4-mapped IPv6 address is reported as IPv4.
	struct gadget_l4endpoint_t dst;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} events SEC(".maps");
GADGET_TRACER(verdict, events, event);

struct net_dst {
	__u8 addr[16]; // IPv6, or IPv4-mapped
	__u16 port; // host byte order
};

// net_parse reads a kernel copy of a sockaddr. Returns 1 when d holds the
// destination, 0 when there is no destination to judge, -1 when the address is
// not IPv4 or IPv6 (judged by the default). unspec_v6: a send on this AF_INET6
// socket treats AF_UNSPEC as AF_INET6.
static __always_inline int net_parse(const void *sa, int len, __u16 skfam,
				     bool is_send, bool unspec_v6,
				     struct net_dst *d)
{
	__u16 family = 0;
	__u16 port = 0;

	if (len < 2 || bpf_probe_read_kernel(&family, sizeof(family), sa))
		return -1;
	if (family == AF_UNSPEC) {
		// connect(AF_UNSPEC) disconnects. A send on an AF_INET socket
		// treats AF_UNSPEC as AF_INET. On AF_INET6, raw and L2TP/IP
		// sends treat it as AF_INET6 (rawv6_sendmsg, l2tp_ip6_sendmsg);
		// the other sends use the peer (udpv6_sendmsg) or refuse it.
		if (!is_send)
			return 0;
		if (skfam == AF_INET)
			family = AF_INET;
		else if (unspec_v6)
			family = AF_INET6;
		else
			return 0;
	}
	if (family == AF_INET) {
		if (len < 8 || bpf_probe_read_kernel(&port, 2, sa + 2) ||
		    bpf_probe_read_kernel(d->addr + 12, 4, sa + 4))
			return -1;
		d->addr[10] = 0xff;
		d->addr[11] = 0xff;
	} else if (family == AF_INET6) {
		if (len < 24 || bpf_probe_read_kernel(&port, 2, sa + 2) ||
		    bpf_probe_read_kernel(d->addr, 16, sa + 8))
			return -1;
	} else {
		return -1;
	}
	d->port = bpf_ntohs(port);
	return 1;
}

static __always_inline bool net_is_mapped(const __u8 *a)
{
	for (int i = 0; i < 10; i++)
		if (a[i])
			return false;
	return a[10] == 0xff && a[11] == 0xff;
}

static __always_inline int net_verdict(enum net_hook hook,
				       const struct net_slot *s, __u64 cgid,
				       __u32 slot, __u16 ipproto,
				       const struct net_dst *d,
				       const struct policy_match *m)
{
	struct event *e;
	bool reporting;

	if (m->rank < POLICY_RANK_DENY_AUDIT) {
		verdict_count(VERDICT_COUNT_ALLOWED);
		return 0;
	}
	verdict_count(VERDICT_COUNT_DENIED);

	reporting = verdict_report_allowed();
	e = reporting ? bpf_ringbuf_reserve(&events, sizeof(*e), 0) : NULL;
	if (e) {
		__builtin_memset(e, 0, sizeof(*e));
		VERDICT_FILL_BASE(e, m, s->def.generation, cgid);
		e->host_pid = bpf_get_current_pid_tgid() >> 32;
		e->rule_id = m->rule_id;
		e->origin_id = m->origin_id;
		e->is_default = m->is_default;
		e->slot = slot;
		bpf_get_current_comm(e->comm, sizeof(e->comm));
		e->hook_raw = hook;
		e->dst.port = d->port;
		e->dst.proto_raw = ipproto;
		if (net_is_mapped(d->addr)) {
			e->dst.version = 4;
			__builtin_memcpy(&e->dst.addr_raw.v4, d->addr + 12, 4);
		} else {
			e->dst.version = 6;
			__builtin_memcpy(e->dst.addr_raw.v6, d->addr, 16);
		}
		bpf_ringbuf_submit(e, 0);
		verdict_count(VERDICT_COUNT_SUBMITTED);
	} else {
		verdict_count(reporting ? VERDICT_COUNT_DROPPED :
					  VERDICT_COUNT_RATE_LIMITED);
	}

	// Keep explicit signed errno branches visible to the verifier.
	volatile int result = 0;
	if (m->rank == POLICY_RANK_DENY_ENFORCE)
		result = -EPERM;
	return result;
}

// net_fault_report exports a structural fault as a network verdict (hook
// fault, no destination): enforce for a Strict binding, which denies, audit
// for an Audit binding, which allows. generation is the slot's (0 when the
// slot has no policy).
static __always_inline void net_fault_report(__u64 cgid, __u32 slot,
					     __u64 generation, bool denied)
{
	struct event *e;

	if (denied)
		verdict_count(VERDICT_COUNT_DENIED);
	if (!verdict_report_allowed()) {
		verdict_count(VERDICT_COUNT_RATE_LIMITED);
		return;
	}
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		verdict_count(VERDICT_COUNT_DROPPED);
		return;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->generation = generation;
	e->cgroup = cgid;
	e->deny = 1;
	e->mode = denied ? POLICY_MODE_ENFORCE : POLICY_MODE_AUDIT;
	e->host_pid = bpf_get_current_pid_tgid() >> 32;
	e->slot = slot;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	e->hook_raw = NET_HOOK_FAULT;
	bpf_ringbuf_submit(e, 0);
	verdict_count(VERDICT_COUNT_SUBMITTED);
}

// net_bound returns the slot header of the current task's bound cgroup, or
// NULL when the task is not judged. A bound cgroup whose slot has no policy
// (never written: generation 0), or a task outside a Strict binding's exact
// scope, is a structural fault, not an unbound task: it counts a section
// error, and for a Strict binding a slot fault and *fault, which denies. An
// Audit binding allows. Both send a fault verdict.
static __always_inline const struct net_slot *net_bound(__u64 *cgid,
							__u32 *slot,
							bool *fault)
{
	const struct net_slot *s;
	__u32 flags = 0;

	*fault = false;
	if (!binding_lookup(cgid, slot, &flags))
		return NULL;
	s = bpf_map_lookup_elem(&net_slots, slot);
	if (!s || !s->def.generation || (flags & BINDING_OUTSIDE_SCOPE)) {
		verdict_count(VERDICT_COUNT_SECTION_ERROR);
		if (flags & BINDING_STRICT) {
			net_slot_fault(*slot);
			*fault = true;
		}
		net_fault_report(*cgid, *slot, s ? s->def.generation : 0,
				 *fault);
		return NULL;
	}
	return net_slot_get(*slot);
}

// net_judge is the common body of the LSM hooks. sa is the kernel copy of the
// destination address, or NULL (a send on a connected socket, judged at
// connect). msg_flags are the send flags (0 for connect).
static __always_inline int net_judge(enum net_hook hook, struct socket *sock,
				     const void *sa, int len, bool is_send,
				     __u32 msg_flags)
{
	struct policy_match m = {};
	const struct net_slot *s;
	struct net_dst d = {};
	__u64 cgid = 0;
	__u32 slot = 0;
	struct sock *sk;
	__u16 skfam, ipproto;
	bool unspec_v6, fault;
	int parsed;

	if (!sa)
		return 0;
	// Only inet sockets are in the section's scope, also for a fault (AF_UNIX
	// and AF_NETLINK sends, for example glibc's name resolution, stay
	// allowed).
	sk = BPF_CORE_READ(sock, sk);
	skfam = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (skfam != AF_INET && skfam != AF_INET6)
		return 0;
	s = net_bound(&cgid, &slot, &fault);
	if (!s)
		return fault ? -EPERM : 0;
	ipproto = BPF_CORE_READ(sk, sk_protocol);
	// TCP and MPTCP use the address of a send only to connect a closed
	// socket (Fast Open). A send without MSG_FASTOPEN on a socket that is
	// not closed does not use it (the connect was judged, and a
	// TCP_FASTOPEN_CONNECT socket is connecting), so it is not judged. A
	// MSG_FASTOPEN send is always judged: the state read here is not under
	// the socket lock, and a concurrent connect(AF_UNSPEC) or shutdown can
	// close the socket before tcp_sendmsg connects it. On a connected
	// socket a denied MSG_FASTOPEN send so fails with EPERM, not EISCONN.
	if (is_send &&
	    (ipproto == NET_IPPROTO_TCP || ipproto == NET_IPPROTO_MPTCP) &&
	    !(msg_flags & NET_MSG_FASTOPEN) &&
	    BPF_CORE_READ(sk, __sk_common.skc_state) != NET_TCP_CLOSE)
		return 0;
	unspec_v6 = skfam == AF_INET6 &&
		    (BPF_CORE_READ(sk, sk_type) == NET_SOCK_RAW ||
		     ipproto == NET_IPPROTO_L2TP);
	parsed = net_parse(sa, len, skfam, is_send, unspec_v6, &d);
	if (parsed == 0)
		return 0;
	if (parsed > 0)
		net_decide(slot, s, d.addr, d.port, net_proto_of(ipproto), &m);
	else
		policy_take(&m, &s->def, true);
	return net_verdict(hook, s, cgid, slot, ipproto, &d, &m);
}

// ret is the verdict of the BPF LSM programs that ran before this one. A
// nonzero verdict is returned as is, so this program never replaces a deny.
// (The kernel trampoline already skips the next programs after a nonzero
// verdict; the check does not depend on that.) ret is read by position:
// socket_connect and socket_sendmsg have had the same three arguments since
// BPF LSM was added in Linux 5.7.
SEC("lsm/socket_connect")
int BPF_PROG(ig_net_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen, int ret)
{
	if (ret) return ret;
	return net_judge(NET_HOOK_SOCKET_CONNECT, sock, address, addrlen, false,
			 0);
}

// Covers sendto, sendmsg, sendmmsg (once per message), TCP Fast Open and
// io_uring sends (IORING_OP_SEND, SENDMSG, SEND_ZC, SENDMSG_ZC). msg_flags
// are set before the hook on all of these paths.
SEC("lsm/socket_sendmsg")
int BPF_PROG(ig_net_sendmsg, struct socket *sock, struct msghdr *msg, int size,
	     int ret)
{
	if (ret) return ret;
	return net_judge(NET_HOOK_SOCKET_SENDMSG, sock,
			 BPF_CORE_READ(msg, msg_name),
			 BPF_CORE_READ(msg, msg_namelen), true,
			 BPF_CORE_READ(msg, msg_flags));
}
