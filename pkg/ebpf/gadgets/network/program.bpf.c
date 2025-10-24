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
unsigned long long load_half(const void *skb,
    unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(const void *skb,
    unsigned long long off) asm("llvm.bpf.load.word");

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
	if (bpf_ntohs(ethh.h_proto) != ETH_P_IP)
		return 0;

	int ip_off = ETH_HLEN;
	// Read the IP header.
	struct iphdr iph;
	if (bpf_skb_load_bytes(skb, ip_off, &iph, sizeof(iph)))
		return 0;

    // An IPv4 header doesn't have a fixed size. The IHL field of a packet
    // represents the size of the IP header in 32-bit words, so we need to
    // multiply this value by 4 to get the header size in bytes.
    // Avoid taking the address of the bit-field; read the first byte from skb.
    __u8 ihl_byte = load_byte(skb, ip_off);
    __u8 ip_header_len = (ihl_byte & 0x0F) * 4;
	int l4_off = ip_off + ip_header_len;
	__u16 port;

	if (iph.protocol == IPPROTO_TCP) {
		// Read the TCP header.
		struct tcphdr tcph;
		if (bpf_skb_load_bytes(skb, l4_off, &tcph, sizeof(tcph)))
			return 0;

        if (!tcph.syn || tcph.ack)
			return 0;

        // Access direct field from the parsed header (network byte order kept)
        port = tcph.dest;
	} else if (iph.protocol == IPPROTO_UDP) {
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

	event->netns_id = skb->cb[0]; // cb[0] initialized by dispatcher.bpf.c
    event->timestamp_raw = bpf_ktime_get_ns();

    if (skb->pkt_type == PACKET_HOST) {
        // Read from skb buffer to avoid taking addresses of bit-fields/stack
        event->endpoint.addr_raw.v4 = load_word(skb, ETH_HLEN + offsetof(struct iphdr, saddr));
    } else {
        event->endpoint.addr_raw.v4 = load_word(skb, ETH_HLEN + offsetof(struct iphdr, daddr));
    }
    // Normalize to network byte order for userspace consumers
    event->endpoint.addr_raw.v4 = event->endpoint.addr_raw.v4;
    event->endpoint.proto_raw = iph.protocol;
	event->endpoint.port = bpf_ntohs(port);
	event->endpoint.version = 4;
	event->egress = skb->pkt_type == PACKET_OUTGOING;

    bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

	return 0;
}

char _license[] SEC("license") = "GPL";