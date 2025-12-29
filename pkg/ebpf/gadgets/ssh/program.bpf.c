#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/types.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GADGET_TYPE_NETWORKING

#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/sockets-map.h>
#include <gadget/filter.h>

// The data structure for events sent to userspace.
struct event_t {
	gadget_timestamp timestamp_raw;
	gadget_netns_id netns_id;
	struct gadget_process proc;
	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;
};

// eBPF map to send events to userspace via a perf ring buffer.
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

GADGET_TRACER(ssh, events, event_t);

// Per-CPU scratch map to build the event before sending it.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct event_t));
} tmp_events SEC(".maps");

// Helper functions to load data from the packet buffer (__sk_buff)
unsigned long long load_byte(const void *skb,
    unsigned long long off) asm("llvm.bpf.load.byte");

SEC("socket1")
int ig_trace_ssh(struct __sk_buff *skb)
{
	struct event_t *event;
	int zero = 0;
	__u16 l4_off;
	struct iphdr iph;
	struct ipv6hdr ip6h;
	struct ethhdr ethh;
	__u8 ip_version = 0;
	__be32 src_addr_v4 = 0;
	__be32 dst_addr_v4 = 0;

	// Step 1: Parse Ethernet header to get the Layer 3 protocol (IPv4 or IPv6)
	if (bpf_skb_load_bytes(skb, 0, &ethh, sizeof(ethh)) < 0)
		return 0;

	// Step 2: Parse IP header to find the start of the Layer 4 header (TCP)
	switch (bpf_ntohs(ethh.h_proto)) {
	case ETH_P_IP: { // IPv4
		if (bpf_skb_load_bytes(skb, ETH_HLEN, &iph, sizeof(iph)) < 0)
			return 0;

		if (iph.protocol != IPPROTO_TCP)
			return 0; // Not a TCP packet, so it can't be SSH

		// An IPv4 header doesn't have a fixed size. The IHL field of a packet
		// represents the size of the IP header in 32-bit words, so we need to
		// multiply this value by 4 to get the header size in bytes.
		// Avoid taking the address of the bit-field; read the first byte from skb.
		__u8 ihl_byte = load_byte(skb, ETH_HLEN);
		__u8 ip_header_len = (ihl_byte & 0x0F) * 4;
		l4_off = ETH_HLEN + ip_header_len;
		
		// Store IPv4 addresses immediately after parsing to avoid verifier issues
		ip_version = 4;
		src_addr_v4 = iph.saddr;
		dst_addr_v4 = iph.daddr;
		break;
	}
	case ETH_P_IPV6: { // IPv6
		if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip6h, sizeof(ip6h)) < 0)
			return 0;

		// Basic check, doesn't handle all IPv6 extension headers
		if (ip6h.nexthdr != IPPROTO_TCP)
			return 0; // Not a TCP packet

		l4_off = ETH_HLEN + sizeof(struct ipv6hdr);
		ip_version = 6;
		break;
	}
	default:
		return 0;
	}

	// --- SSH Signature Detection Logic ---
	// Instead of checking ports, we look for the "SSH-2.0-" banner.

	// Step 3: Find the start of the TCP payload
	struct tcphdr tcph;
	if (bpf_skb_load_bytes(skb, l4_off, &tcph, sizeof(tcph))< 0)
		return 0;

	// TCP header length can vary. 'doff' is in 32-bit words.
	// Avoid taking the address of the bit-field; read the byte from skb.
	// Byte 12 of TCP header contains: data offset (upper 4 bits) and reserved (lower 4 bits)
	__u8 doff_byte = load_byte(skb, l4_off + 12);
	__u32 tcp_header_len = ((doff_byte >> 4) & 0x0F) * 4;
	__u32 payload_offset = l4_off + tcp_header_len;

	// Ensure the packet is long enough to contain the SSH banner.
	// We need to check for at least 8 bytes "SSH-2.0-".
	if (payload_offset + 8 > skb->len)
		return 0;

	// Step 4: Read the first 8 bytes of the TCP payload.
	char banner[8];
	if (bpf_skb_load_bytes(skb, payload_offset, banner, sizeof(banner)) < 0)
		return 0;

	// Step 5: Compare the payload against the known SSH signature.
	// This is the core of the protocol detection.
	if (banner[0] != 'S' || banner[1] != 'S' || banner[2] != 'H' ||
	    banner[3] != '-' || banner[4] != '2' || banner[5] != '.' ||
	    banner[6] != '0' || banner[7] != '-') {
		return 0;
	}
	
	// --- Event Population (if signature matched) ---

	// Step 6: Get a temporary event struct to fill
	event = bpf_map_lookup_elem(&tmp_events, &zero);
	if (!event)
		return 0;

	// Step 7: Populate the event with collected data
	event->timestamp_raw = bpf_ktime_get_boot_ns();
	event->netns_id = skb->cb[0]; // Filled by the dispatcher
	event->src.port = bpf_ntohs(tcph.source);
	event->dst.port = bpf_ntohs(tcph.dest);
	event->src.proto_raw = event->dst.proto_raw = IPPROTO_TCP;

	// Fill source and destination IP addresses
	event->src.version = event->dst.version = ip_version;
	if (ip_version == 4) {
		// Use stored IPv4 addresses to avoid verifier issues with cross-switch access
		event->src.addr_raw.v4 = src_addr_v4;
		event->dst.addr_raw.v4 = dst_addr_v4;
	} else if (ip_version == 6) {
		// Read IPv6 addresses from packet buffer using offsets
		// This avoids nested struct access that the verifier on kernel 5.4 cannot track properly
		// IPv6 source address is at offset ETH_HLEN + 8 (bytes 8-23 of IPv6 header)
		// IPv6 destination address is at offset ETH_HLEN + 24 (bytes 24-39 of IPv6 header)
		if (bpf_skb_load_bytes(skb, ETH_HLEN + 8, &event->src.addr_raw.v6[0], 16))
			return 0;
		if (bpf_skb_load_bytes(skb, ETH_HLEN + 24, &event->dst.addr_raw.v6[0], 16))
			return 0;
	}

	// Step 8: Enrich the event with process information
	struct gadget_socket_value *skb_val = gadget_socket_lookup(skb);
    if (gadget_should_discard_data_by_skb(skb_val))
		return 0;
	gadget_process_populate_from_socket(skb_val, &event->proc);

	// Step 9: Send the populated event to userspace
	bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, event,
			      sizeof(*event));

	return 0;
}

char _license[] SEC("license") = "GPL";
