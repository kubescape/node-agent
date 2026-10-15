static struct event_t captured;
static void *bpf_map_lookup_elem(void *map, const void *key) { return &captured; }

static void check(int version, int direction, int proto, int port, int flags, int options, bool want) {
 memset(packet, 0, sizeof(packet));
 memset(&captured, 0xa5, sizeof(captured));
 struct ethhdr *eth = (void *)packet;
 eth->h_proto = htons(version == 4 ? ETH_P_IP : ETH_P_IPV6);
 unsigned off;
 unsigned char expected[16];
 if (version == 4) {
  struct iphdr ip = {.version=4, .ihl=5+options, .protocol=proto};
  inet_pton(AF_INET, "10.1.2.3", &ip.saddr);
  inet_pton(AF_INET, "192.0.2.9", &ip.daddr);
  memcpy(packet+ETH_HLEN, &ip, sizeof(ip));
  memcpy(expected, direction == PACKET_HOST ? &ip.saddr : &ip.daddr, 4);
  off = ETH_HLEN + ip.ihl*4;
 } else {
  struct ipv6hdr ip = {.version=6, .nexthdr=proto};
  inet_pton(AF_INET6, "fd00::1234", &ip.saddr);
  inet_pton(AF_INET6, "2001:db8::5678", &ip.daddr);
  memcpy(expected, direction == PACKET_HOST ? &ip.saddr : &ip.daddr, 16);
  memcpy(packet+ETH_HLEN, &ip, sizeof(ip));
  off = ETH_HLEN + sizeof(ip);
 }
 unsigned size;
 if (proto == IPPROTO_TCP) {
  struct tcphdr tcp = {.source=htons(50000), .dest=htons(port), .syn=!!(flags&1), .ack=!!(flags&2)};
  memcpy(packet+off, &tcp, sizeof(tcp)); size = sizeof(tcp);
 } else {
  struct udphdr udp = {.source=htons(50000), .dest=htons(port)};
  memcpy(packet+off, &udp, sizeof(udp)); size = sizeof(udp);
 }
 struct __sk_buff skb = {.len=off+size, .pkt_type=direction, .cb={99}};
 emitted = 0;
 ig_trace_net(&skb);
 assert(emitted == want);
 if (want) {
  assert(captured.endpoint.version == version);
  assert(captured.endpoint.proto_raw == proto);
  assert(captured.endpoint.port == port);
  assert(!memcmp(&captured.endpoint.addr_raw, expected, version == 4 ? 4 : 16));
  assert(captured.egress == (direction == PACKET_OUTGOING));
  assert(captured.proc.pid == 42 && captured.netns_id == 99 && captured.timestamp_raw == 123);
 }
 // Every truncated prefix must be rejected, without reading stale bytes.
 for (unsigned n=0; n<off+size; n++) {
  skb.len=n; emitted=0; ig_trace_net(&skb); assert(emitted == 0);
 }
}
static void check_path(const char *expected) {
 check(4, PACKET_OUTGOING, IPPROTO_TCP, 10250, 1, 0, true);
 assert(!strcmp(captured.exepath, expected));
}
int main(void) {
 for (int v=4; v<=6; v+=2) {
  for (int d=PACKET_HOST; d<=PACKET_OUTGOING; d+=4) {
   check(v,d,IPPROTO_TCP,10250,1,0,true);
   check(v,d,IPPROTO_TCP,443,3,0,false);
   check(v,d,IPPROTO_TCP,443,0,0,false);
   check(v,d,IPPROTO_UDP,53,0,0,true);
   check(v,d,IPPROTO_UDP,1024,0,0,false);
   check(v,d,IPPROTO_ICMP,53,0,0,false);
  }
  check(v,1,IPPROTO_TCP,10250,1,0,false);
  discard=true; check(v,PACKET_OUTGOING,IPPROTO_TCP,10250,1,0,false); discard=false;
 }
 check(4,PACKET_OUTGOING,IPPROTO_TCP,10250,1,1,true);
 strcpy(socket_value.exepath, "/usr/bin/curl");
 check_path("/usr/bin/curl");
 strcpy(socket_value.exepath, "/tmp/renamed-client");
 check_path("/tmp/renamed-client");
 socket_available = false; check_path(""); socket_available = true;
 path_exists = false; check_path(""); path_exists = true;
 socket_value.exepath[0] = 0; check_path("");
 memset(socket_value.exepath, 'a', sizeof(socket_value.exepath));
 check(4, PACKET_OUTGOING, IPPROTO_TCP, 10250, 1, 0, true);
 assert(strlen(captured.exepath) == NETWORK_PATH_MAX - 1);
 assert(captured.exepath[NETWORK_PATH_MAX - 1] == 0);
 path_size = 16;
 check(4, PACKET_OUTGOING, IPPROTO_TCP, 10250, 1, 0, true);
 assert(strlen(captured.exepath) == path_size - 1);
 path_size = 1; check_path("");
 path_size = 0; check_path("");
 return 0;
}
