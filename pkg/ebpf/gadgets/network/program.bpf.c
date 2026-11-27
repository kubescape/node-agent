// vmlinux.h instead of the linux/*.h UAPI headers: the tcp_connect kprobe
// reads struct sock and struct task_struct with CO-RE.
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/maps.bpf.h>

#define GADGET_TYPE_NETWORKING
#include <gadget/sockets-map.h>
#include <gadget/filter.h>

#include "program.h"

#ifndef ETH_HLEN
#define ETH_HLEN 14
#endif
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

// we need this to make sure the compiler doesn't remove our struct
const struct event_t *unusedevent __attribute__((unused));

// Owner of each outgoing TCP connection, keyed by its full 4-tuple and
// filled by the tcp_connect kprobe (tcp_connect.bpf.h) just before the SYN is
// sent. The socket enricher keys its map by local port only and keeps the
// first socket on a port, so when a host process reuses a local port that a
// host-network container process already holds (allowed when the remote
// endpoints differ), the port lookup returns the container process. The
// 4-tuple identifies the connection that sent the SYN. LRU: entries are only
// needed until the SYN (and its retransmits) pass the filter, and a newer
// connect of the same 4-tuple overwrites the entry, so nothing is deleted.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, NETWORK_CONNECT_OWNERS_MAX);
	__uint(key_size, sizeof(struct connect_key));
	__uint(value_size, sizeof(struct connect_owner));
} connect_owners SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct event_t));
} tmp_events SEC(".maps");

// Define a tracer
GADGET_TRACER(network, events, event_t);

static __always_inline void
populate_from_connect_owner(const struct connect_owner *owner,
			    struct gadget_process *p)
{
	__builtin_memcpy(p->comm, owner->task, sizeof(p->comm));
	p->pid = owner->pid_tgid >> 32;
	p->tid = (__u32)owner->pid_tgid;
	p->mntns_id = owner->mntns;
	p->creds.uid = (__u32)owner->uid_gid;
	p->creds.gid = owner->uid_gid >> 32;
	__builtin_memcpy(p->parent.comm, owner->ptask, sizeof(p->parent.comm));
	p->parent.pid = owner->ppid;
	p->parent.tid = owner->ptid;
}

// Helper functions to load data from the packet buffer (__sk_buff)
unsigned long long load_byte(const void *skb,
    unsigned long long off) asm("llvm.bpf.load.byte");

SEC("socket1")
int ig_trace_net(struct __sk_buff *skb)
{
	// Skip multicast, broadcast, forwarding...
	// Read the context field once: with several reads, clang may keep a
	// ctx+offset pointer around, which the verifier rejects.
	__u32 pkt_type = skb->pkt_type;
	if (pkt_type != PACKET_HOST && pkt_type != PACKET_OUTGOING)
		return 0;

	// Skip frames with non-IP Ethernet protocol.
	struct ethhdr ethh;
	if (bpf_skb_load_bytes(skb, 0, &ethh, sizeof(ethh)))
		return 0;
	struct iphdr iph = {};
	struct ipv6hdr ip6h;
	__u8 version;
	__u8 protocol;
	int l4_off;

	switch (bpf_ntohs(ethh.h_proto)) {
	case ETH_P_IP: {
		if (bpf_skb_load_bytes(skb, ETH_HLEN, &iph, sizeof(iph)))
			return 0;
		__u8 ihl_byte = load_byte(skb, ETH_HLEN);
		__u8 ip_header_len = (ihl_byte & 0x0F) * 4;
		if (iph.version != 4 || ip_header_len < sizeof(iph))
			return 0;
		l4_off = ETH_HLEN + ip_header_len;
		protocol = iph.protocol;
		version = 4;
		break;
	}
	case ETH_P_IPV6:
		if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip6h, sizeof(ip6h)))
			return 0;
		if (ip6h.version != 6)
			return 0;
		l4_off = ETH_HLEN + sizeof(ip6h);
		// As with the SSH gadget, extension headers are not traversed.
		protocol = ip6h.nexthdr;
		version = 6;
		break;
	default:
		return 0;
	}

	__u16 port;
	struct connect_owner *owner = NULL;

	if (protocol == IPPROTO_TCP) {
		// Read the TCP header.
		struct tcphdr tcph;
		if (bpf_skb_load_bytes(skb, l4_off, &tcph, sizeof(tcph)))
			return 0;

        if (!tcph.syn || tcph.ack)
			return 0;

        // Access direct field from the parsed header (network byte order kept)
        port = tcph.dest;

        // An outgoing SYN belongs to the task that called connect() for
        // exactly this 4-tuple. The port-keyed socket map below cannot tell
        // two connections sharing a local port apart.
        if (pkt_type == PACKET_OUTGOING) {
            struct connect_key key;
            __builtin_memset(&key, 0, sizeof(key));
            key.netns = skb->cb[0]; // cb[0] initialized by dispatcher.bpf.c
            key.lport = bpf_ntohs(tcph.source);
            key.rport = bpf_ntohs(tcph.dest);
            key.version = version;
            if (version == 4) {
                __builtin_memcpy(key.laddr, &iph.saddr, 4);
                __builtin_memcpy(key.raddr, &iph.daddr, 4);
            } else {
                __builtin_memcpy(key.laddr, &ip6h.saddr, 16);
                __builtin_memcpy(key.raddr, &ip6h.daddr, 16);
            }
            owner = bpf_map_lookup_elem(&connect_owners, &key);
        }
	} else if (protocol == IPPROTO_UDP) {
		// Read the UDP header.
		struct udphdr udph;
		if (bpf_skb_load_bytes(skb, l4_off, &udph, sizeof(udph)))
			return 0;

		// UDP packets don't have a TCP-SYN to identify the direction.
		// Check usage of dynamic ports instead.
		// https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
		// System Ports: 0-1023
		// User Ports: 1024-49151
		// Dynamic and/or Private Ports: 49152-65535
		// However, Linux uses ephemeral ports: 32768-60999 (/proc/sys/net/ipv4/ip_local_port_range)
		// And /proc/sys/net/ipv4/ip_unprivileged_port_start: 1024
        __u16 udp_dest_host = bpf_ntohs(udph.dest);
        if (udp_dest_host < 1024)
            // Keep network byte order in the event, as with TCP
            port = udph.dest;
		else
			return 0;
	} else {
		// Skip packets with IP protocol other than TCP/UDP.
		return 0;
	}

    // Without a 4-tuple owner (UDP, ingress, a connection made before the
    // gadget started, or an LRU eviction), fall back to the port-keyed lookup.
    struct gadget_socket_value *skb_val = NULL;
    if (owner) {
        if (gadget_should_discard_data(owner->mntns, owner->pid_tgid >> 32,
                                       (__u32)owner->pid_tgid, owner->task,
                                       (__u32)owner->uid_gid,
                                       owner->uid_gid >> 32))
            return 0;
    } else {
        skb_val = gadget_socket_lookup(skb);
        if (gadget_should_discard_data_by_skb(skb_val))
            return 0;
    }

    __u32 zero = 0;
    struct event_t *event = bpf_map_lookup_elem(&tmp_events, &zero);
    if (!event)
        return 0;

    const char *exepath = NULL;
    unsigned int exepath_len = 0;
    if (owner) {
        populate_from_connect_owner(owner, &event->proc);
        exepath = owner->exepath;
        exepath_len = sizeof(owner->exepath);
    } else {
        gadget_process_populate_from_socket(skb_val, &event->proc);
        if (skb_val && bpf_core_field_exists(skb_val->exepath)) {
            exepath_len = bpf_core_field_size(skb_val->exepath);
            exepath = (const char *)skb_val +
                      bpf_core_field_offset(skb_val->exepath);
        }
    }

    // The path is a map value: copy directly without a kernel-read helper,
    // which socket filters cannot use on some kernels/lockdown modes.
    // tmp_events is reused, so missing attribution must clear the previous path.
    event->exepath[0] = '\0';
    if (exepath) {
#pragma unroll
        for (int i = 0; i < NETWORK_PATH_MAX; i++) {
            if (i + 1 >= exepath_len || i == NETWORK_PATH_MAX - 1) {
                event->exepath[i] = '\0';
                break;
            }
            char c = exepath[i];
            event->exepath[i] = c;
            if (!c)
                break;
        }
    }

	event->netns_id = skb->cb[0]; // cb[0] initialized by dispatcher.bpf.c
    event->timestamp_raw = bpf_ktime_get_boot_ns();

	if (version == 4) {
		event->endpoint.addr_raw.v4 = pkt_type == PACKET_HOST ? iph.saddr : iph.daddr;
	} else {
		// IPv6 source and destination addresses start at bytes 8 and 24.
		int addr_off = ETH_HLEN + (pkt_type == PACKET_HOST ? 8 : 24);
		if (bpf_skb_load_bytes(skb, addr_off, &event->endpoint.addr_raw.v6[0], 16))
			return 0;
	}
	event->endpoint.proto_raw = protocol;
	event->endpoint.port = bpf_ntohs(port);
	event->endpoint.version = version;
	event->egress = pkt_type == PACKET_OUTGOING;

    bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

	return 0;
}

// Fills connect_owners. Kept in its own file: the native packet harness
// (tests/packet_test.go) drops #include lines and does not build the kprobe.
#include "tcp_connect.bpf.h"

char _license[] SEC("license") = "GPL";
