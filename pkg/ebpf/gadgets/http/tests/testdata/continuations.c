#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
typedef uint64_t __u64;
typedef uint32_t __u32;
typedef uint16_t __u16;
typedef uint8_t __u8;
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint64_t gadget_timestamp;
struct gadget_process {
  int unused;
};
struct gadget_l4endpoint_t {
  int unused;
};
struct syscall_trace_enter {
  uint64_t args[6];
};
struct syscall_trace_exit {
  int64_t ret;
};
struct user_msghdr {
  struct iovec *msg_iov;
  size_t msg_iovlen;
};
#define SEC(x)
#define BPF_ANY 0
#define BPF_MAP_TYPE_PERCPU_ARRAY 1
#define __noinline __attribute__((noinline))
#define __uint(name, val) int name
#define __type(name, val) val *name
#undef __always_inline
#define __always_inline inline
/* PRODUCTION_HEADER */
/* PRODUCTION_METADATA */
/* PRODUCTION_LOSS_ENUM */
static int buffer_packets, msg_packets, http_continuations, events,
    continuation_stats, capture_loss;
static uint64_t losses[HTTP_LOSS_COUNT];
static uint64_t stats[HTTP_CONTINUATION_STAT_COUNT];
static bool fail_store;
static struct packet_buffer packet;
static struct packet_msg message;
static struct http_continuation continuation;
static struct http_continuation_key continuation_key;
static bool has_packet, has_message, has_continuation, fail_reserve;
static uint64_t now = 1;
static struct httpevent output[100];
static size_t event_count, captured;
static uint64_t bpf_get_current_pid_tgid(void) { return 123; }
static uint64_t bpf_ktime_get_boot_ns(void) { return now; }
static bool gadget_should_discard_data_current(void) { return false; }
static uint64_t get_socket_inode(uint32_t fd) { return fd; }
static uint64_t min_size(uint64_t a, uint64_t b) { return a < b ? a : b; }
static bool is_msg_peek(uint32_t flags) { return flags & MSG_PEEK; }
static int populate_http_metadata(struct http_metadata *e, uint32_t fd,
                                  bool rx) {
  (void)rx;
  e->socket_inode = fd;
  return 0;
}
static void *bpf_map_lookup_elem(void *map, const void *key);
static int bpf_map_update_elem(void *map, const void *key, const void *value,
                               int flags) {
  (void)flags;
  if (map == &buffer_packets) {
    packet = *(const struct packet_buffer *)value;
    has_packet = true;
  } else if (map == &msg_packets) {
    message = *(const struct packet_msg *)value;
    has_message = true;
  } else {
    if (fail_store)
      return -1;
    continuation = *(const struct http_continuation *)value;
    continuation_key = *(const struct http_continuation_key *)key;
    has_continuation = true;
  }
  return 0;
}
static int bpf_map_delete_elem(void *map, const void *key) {
  (void)key;
  if (map == &buffer_packets)
    has_packet = false;
  else if (map == &msg_packets)
    has_message = false;
  else
    has_continuation = false;
  return 0;
}
static int bpf_probe_read(void *dst, size_t len, const void *src) { memcpy(dst, src, len); return 0; }
static int bpf_probe_read_user(void *dst, size_t len, const void *src) {
  if (!src)
    return -1;
  memcpy(dst, src, len);
  return 0;
}
static int bpf_probe_read_str(void *dst, size_t len, const char *src) {
  snprintf(dst, len, "%s", src);
  return 0;
}
static void *gadget_reserve_buf(void *map, size_t len) {
  (void)map;
  (void)len;
  return fail_reserve ? NULL : &output[event_count];
}
static void gadget_discard_buf(void *event) { (void)event; }
static void gadget_submit_buf(void *ctx, void *map, struct httpevent *e,
                              size_t len) {
  (void)ctx;
  (void)map;
  (void)len;
  captured += e->buf_len;
  event_count++;
}
/* PRODUCTION_PROBES */
static void *bpf_map_lookup_elem(void *map, const void *key) {
  static struct payload_args scratch;
  static struct http_aggregate aggregate;
  if (map == &aggregate_scratch) return &aggregate;
  if (map == &payload_scratch)
    return &scratch;
  if (map == &capture_loss)
    return &losses[*(const uint32_t *)key];
  if (map == &continuation_stats)
    return &stats[*(const uint32_t *)key];
  if (map == &buffer_packets)
    return has_packet ? &packet : NULL;
  if (map == &msg_packets)
    return has_message ? &message : NULL;
  const struct http_continuation_key *k = key;
  return has_continuation && k->socket_inode == continuation_key.socket_inode &&
                 k->is_rx == continuation_key.is_rx
             ? &continuation
             : NULL;
}

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "line %d: %s (events=%zu bytes=%zu)\n", __LINE__, #x,    \
              event_count, captured);                                          \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static char headers[256] = "HTTP/1.1 200 OK\r\nContent-Length: 32768\r\n\r\n";
static char body[32768];
static void receive(const char *kind, char *buf, size_t len) {
  struct syscall_trace_enter enter = {.args = {1, (uint64_t)buf, len}};
  struct syscall_trace_exit leave = {.ret = len};
  struct iovec iov = {.iov_base = buf, .iov_len = len};
  struct user_msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};
  if (!strcmp(kind, "read")) {
    sys_enter_read(&enter);
    sys_exit_read(&leave);
  } else if (!strcmp(kind, "readv")) {
    enter.args[1] = (uint64_t)&iov;
    enter.args[2] = 1;
    syscall__probe_entry_readv(&enter);
    syscall__probe_ret_readv(&leave);
  } else {
    enter.args[1] = (uint64_t)&msg;
    enter.args[2] = 0;
    syscall__probe_entry_recvmsg(&enter);
    syscall__probe_ret_recvmsg(&leave);
  }
}
int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  for (size_t i = 0; i < sizeof(body); i++) body[i] = (char)((i * 31 + 17) % 251);
  const char *which = argv[1];
  if (!strncmp(which, "large_", 6)) {
    receive(which + 6, headers, strlen(headers));
    receive(which + 6, body, sizeof(body));
    CHECK(captured == strlen(headers) + sizeof(body));
    CHECK(event_count == 3);
    CHECK(!memcmp(output[1].buf, body, 16384));
    CHECK(!memcmp(output[2].buf, body + 16384, 16384));
  } else if (!strncmp(which, "split_", 6) || !strcmp(which, "mixed_partial")) {
    // Empty vectors interspersed with headers and mixed body lengths.
    struct iovec iov[] = {
        {NULL, 0}, {headers, strlen(headers)}, {body, 3000}, {NULL, 0},
        {body + 3000, 10000}, {body + 13000, sizeof(body) - 13000}};
    struct user_msghdr msg = {.msg_iov = iov, .msg_iovlen = 6};
    struct syscall_trace_enter enter = {.args = {1, (uint64_t)iov, 6}};
    struct syscall_trace_exit leave = {.ret = strlen(headers) + sizeof(body)};
    if (!strcmp(which, "mixed_partial")) leave.ret = 21000;
    if (!strcmp(which, "split_readv") || !strcmp(which, "mixed_partial")) {
      syscall__probe_entry_readv(&enter);
      syscall__probe_ret_readv(&leave);
    } else {
      enter.args[1] = (uint64_t)&msg;
      enter.args[2] = 0;
      syscall__probe_entry_recvmsg(&enter);
      syscall__probe_ret_recvmsg(&leave);
    }
    CHECK(captured == (size_t)leave.ret);
    CHECK(event_count == (captured + 16383) / 16384);
    size_t offset = 0;
    for (size_t i = 0; i < event_count; i++) {
      CHECK(output[i].type == EVENT_TYPE_RESPONSE);
      for (size_t j = 0; j < output[i].buf_len; j++, offset++) {
        unsigned char expected = offset < strlen(headers) ? headers[offset] : body[offset - strlen(headers)];
        CHECK(output[i].buf[j] == expected);
      }
    }
    CHECK(offset == captured);
    CHECK(continuation.remaining_bytes ==
          HTTP_CONTINUATION_MAX_BYTES - captured);
  } else if (!strcmp(which, "read") || !strcmp(which, "readv") ||
             !strcmp(which, "recvmsg")) {
    receive(which, headers, strlen(headers));
    for (int i = 0; i < 8; i++)
      receive(which, body, 4096);
    CHECK(captured == strlen(headers) + sizeof(body));
    CHECK(event_count == 9);
    for (size_t i = 1; i < event_count; i++) {
      CHECK(output[i].type == EVENT_TYPE_RESPONSE);
      CHECK(output[i].buf_len == 4096);
      CHECK(!memcmp(output[i].buf, body, 4096));
    }
  } else if (!strcmp(which, "slow_body") || !strcmp(which, "expiry")) {
    receive("read", headers, strlen(headers));
    now += (!strcmp(which, "slow_body") ? 31ULL : 121ULL) * 1000000000;
    receive("read", body, 4096);
    CHECK(event_count == (!strcmp(which, "slow_body") ? 2 : 1));
    if (!strcmp(which, "expiry"))
      CHECK(stats[HTTP_CONTINUATION_EXPIRED] == 1);
  } else if (!strcmp(which, "store_failed")) {
    fail_store = true;
    receive("read", headers, strlen(headers));
    CHECK(stats[HTTP_CONTINUATION_STORE_FAILED] == 1);
    CHECK(!has_continuation);
    receive("read", body, 4096);
    CHECK(event_count == 1);
    CHECK(stats[HTTP_CONTINUATION_MISS] == 1);
  } else if (!strcmp(which, "refresh")) {
    receive("read", headers, strlen(headers));
    for (int i = 0; i < 3; i++) {
      now += 119ULL * 1000000000;
      receive("read", body, 4096);
    }
    CHECK(event_count == 4);
    CHECK(stats[HTTP_CONTINUATION_EXPIRED] == 0);
  } else if (!strcmp(which, "budget")) {
    receive("read", headers, strlen(headers));
    continuation.remaining_bytes = 4096;
    receive("read", body, 4096);
    CHECK(captured == strlen(headers) + 4096);
    CHECK(!has_continuation);
    CHECK(stats[HTTP_CONTINUATION_BUDGET_EXHAUSTED] == 1);
    receive("read", body, 4096);
    CHECK(event_count == 2);
  } else if (!strcmp(which, "peek_scalar")) {
    struct syscall_trace_enter e = {
        .args = {1, (uint64_t)headers, sizeof(headers)}};
    struct syscall_trace_exit x = {.ret = -11};
    sys_enter_read(&e);
    sys_exit_read(&x);
    e.args[3] = MSG_PEEK;
    sys_enter_recvfrom(&e);
    x.ret = strlen(headers);
    sys_exit_recvfrom(&x);
    CHECK(event_count == 0);
    CHECK(!has_continuation);
  } else if (!strcmp(which, "peek_vector") || !strcmp(which, "failed_msghdr")) {
    struct iovec iov = {.iov_base = headers, .iov_len = strlen(headers)};
    struct user_msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};
    struct syscall_trace_enter e = {.args = {1, (uint64_t)&msg, 0}};
    struct syscall_trace_exit first = {.ret = strlen(headers)};
    fail_reserve = true;
    syscall__probe_entry_recvmsg(&e);
    syscall__probe_ret_recvmsg(&first);
    fail_reserve = false;
    e.args[2] = MSG_PEEK;
    if (!strcmp(which, "failed_msghdr")) {
      e.args[1] = 0;
      e.args[2] = 0;
    }
    struct syscall_trace_exit x = {.ret = strlen(headers)};
    syscall__probe_entry_recvmsg(&e);
    syscall__probe_ret_recvmsg(&x);
    CHECK(event_count == 0);
  }
  return 0;
}
