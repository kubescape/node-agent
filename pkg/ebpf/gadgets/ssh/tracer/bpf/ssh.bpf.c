#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/types.h>
#include <sys/socket.h>
#include <stdbool.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../../../../include/macros.h"
#include "../../../../include/buffer.h"

#define GADGET_TYPE_NETWORKING
#include "../../../../include/sockets-map.h"

#include "ssh.h"


// Events map.
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Empty event map.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct event);
} empty_event SEC(".maps");

// we need this to make sure the compiler doesn't remove our struct.
const struct event *unusedevent __attribute__((unused));

SEC("socket")
int ssh_detector(struct __sk_buff *skb) {
    // Check if it's an IP packet
    if (skb->protocol != bpf_htons(ETH_P_IP))
        return 0;

    // Define the offset for IP header
    int ip_offset = ETH_HLEN;

    // Read IP header
    struct iphdr iph;
    if (bpf_skb_load_bytes(skb, ip_offset, &iph, sizeof(iph)) < 0)
        return 0;

    // Check if it's a TCP packet
    if (iph.protocol != IPPROTO_TCP)
        return 0;

    // Calculate TCP header offset
    int tcp_offset = ip_offset + (iph.ihl * 4);

    // Read TCP header
    struct tcphdr tcph;
    if (bpf_skb_load_bytes(skb, tcp_offset, &tcph, sizeof(tcph)) < 0)
        return 0;

    // Calculate payload offset
    int payload_offset = tcp_offset + (tcph.doff * 4);

    // Read the first 4 bytes of the payload
    char payload[SSH_SIG_LEN];
    if (bpf_skb_load_bytes(skb, payload_offset, payload, SSH_SIG_LEN) < 0)
        return 0;

    // Check for SSH signature using memcmp
    if (__builtin_memcmp(payload, SSH_SIGNATURE, SSH_SIG_LEN) == 0) {
        struct event *event;
        __u32 zero = 0;
        event = bpf_map_lookup_elem(&empty_event, &zero);
        if (!event) {
            return 0;
        }

        // Enrich event with process metadata
        struct sockets_value *skb_val = gadget_socket_lookup(skb);
        if (skb_val != NULL) {
            event->netns = skb->cb[0]; // cb[0] initialized by dispatcher.bpf.c
            event->mntns_id = skb_val->mntns;
            event->pid = skb_val->pid_tgid >> 32;
            event->uid = (__u32)(skb_val->uid_gid);
            event->gid = (__u32)(skb_val->uid_gid >> 32);
            __builtin_memcpy(&event->comm, skb_val->task, sizeof(event->comm));

            event->src_ip = bpf_ntohl(iph.saddr);
            event->dst_ip = bpf_ntohl(iph.daddr);
            event->src_port = bpf_ntohs(tcph.source);
            event->dst_port = bpf_ntohs(tcph.dest);

            event->timestamp = bpf_ktime_get_boot_ns();
        }
        __u64 skb_len = skb->len;
        bpf_perf_event_output(skb, &events, skb_len << 32 | BPF_F_CURRENT_CPU, event, sizeof(struct event));
    }

    return 0;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";