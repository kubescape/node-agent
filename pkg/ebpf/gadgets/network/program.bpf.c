#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <stdbool.h>

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

// we need this to make sure the compiler doesn't remove our struct
const struct event_t *unusedevent __attribute__((unused));

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

// Helper functions to load data from the packet buffer (__sk_buff)
unsigned long long load_byte(const void *skb,
    unsigned long long off) asm("llvm.bpf.load.byte");

SEC("socket1")
int ig_trace_net(struct __sk_buff *skb)
{
	// Skip multicast, broadcast, forwarding...
	if (skb->pkt_type != PACKET_HOST && skb->pkt_type != PACKET_OUTGOING)
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

	if (protocol == IPPROTO_TCP) {
		// Read the TCP header.
		struct tcphdr tcph;
		if (bpf_skb_load_bytes(skb, l4_off, &tcph, sizeof(tcph)))
			return 0;

        if (!tcph.syn || tcph.ack)
			return 0;

        // Access direct field from the parsed header (network byte order kept)
        port = tcph.dest;
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

    struct gadget_socket_value *skb_val = gadget_socket_lookup(skb);
    if (gadget_should_discard_data_by_skb(skb_val))
        return 0;

    __u32 zero = 0;
    struct event_t *event = bpf_map_lookup_elem(&tmp_events, &zero);
    if (!event)
        return 0;

    gadget_process_populate_from_socket(skb_val, &event->proc);

    // The socket metadata is a map value: copy directly without a kernel-read
    // helper, which socket filters cannot use on some kernels/lockdown modes.
    // tmp_events is reused, so missing attribution must clear the previous path.
    event->exepath[0] = '\0';
    if (skb_val && bpf_core_field_exists(skb_val->exepath)) {
        unsigned int exepath_len = bpf_core_field_size(skb_val->exepath);
        const char *exepath = (const char *)skb_val +
                             bpf_core_field_offset(skb_val->exepath);
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
		event->endpoint.addr_raw.v4 = skb->pkt_type == PACKET_HOST ? iph.saddr : iph.daddr;
	} else {
		// IPv6 source and destination addresses start at bytes 8 and 24.
		int addr_off = ETH_HLEN + (skb->pkt_type == PACKET_HOST ? 8 : 24);
		if (bpf_skb_load_bytes(skb, addr_off, &event->endpoint.addr_raw.v6[0], 16))
			return 0;
	}
	event->endpoint.proto_raw = protocol;
	event->endpoint.port = bpf_ntohs(port);
	event->endpoint.version = version;
	event->egress = skb->pkt_type == PACKET_OUTGOING;

    bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

	return 0;
}

char _license[] SEC("license") = "GPL";
