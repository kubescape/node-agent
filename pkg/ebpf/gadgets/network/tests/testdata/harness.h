#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#define SEC(s)
#define __uint(name, value) int (*name)[value]
#define GADGET_TRACER(...)
#define bpf_ntohs(x) ntohs(x)
typedef __u64 gadget_timestamp, gadget_netns_id;
struct gadget_process { int pid; };
struct gadget_socket_value { int unused; };
struct gadget_l4endpoint_t {
 union { __u32 v4; __u8 v6[16]; } addr_raw;
 __u16 port;
 __u8 proto_raw, version;
};
static unsigned char packet[256];
static unsigned emitted;
static bool discard;
static struct gadget_socket_value socket_value;
static void *bpf_map_lookup_elem(void *, const void *);
static int bpf_skb_load_bytes(const struct __sk_buff *skb, unsigned off, void *dst, unsigned size) {
 if (off > skb->len || size > skb->len - off) return -1;
 memcpy(dst, packet + off, size); return 0;
}
static unsigned long long load_byte(const void *skb, unsigned long long off) {
 const struct __sk_buff *s = skb;
 return off < s->len ? packet[off] : 0;
}
static struct gadget_socket_value *gadget_socket_lookup(struct __sk_buff *skb) { return &socket_value; }
static bool gadget_should_discard_data_by_skb(struct gadget_socket_value *s) { return discard; }
static void gadget_process_populate_from_socket(struct gadget_socket_value *s, struct gadget_process *p) { p->pid = 42; }
static __u64 bpf_ktime_get_boot_ns(void) { return 123; }
static int bpf_perf_event_output(void *ctx, void *map, __u64 flags, void *data, __u64 size) { emitted++; return 0; }
