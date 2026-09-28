#pragma once

#include <gadget/types.h>

#define EVENT_TYPE_REQUEST 2
#define EVENT_TYPE_RESPONSE 3

#define MAX_PACKET_SIZE 200
#define PACKET_CHUNK_SIZE 200
// Keep one plain-HTTP syscall payload on par with the TLS capture chunk size.
// Larger successful syscall buffers are emitted in bounded chunks; body-only
// later syscalls use the continuation tracking below.
#define MAX_DATAEVENT_BUFFER (16 * 1024)
#define HTTP_MAX_CHUNKS 16
#define MAX_SYSCALL 128
#define MAX_MSG_COUNT 20

// A syscall that starts an HTTP message can be followed by body-only syscalls.
// Keep forwarding those chunks for a bounded period so userspace can reassemble
// the complete message instead of dropping every continuation at classification.
#define HTTP_CONTINUATION_MAX_BYTES (256 * 1024)
// Allow slow response bodies to resume throughout a two-minute idle window.
// The fixed-size LRU and byte budget still bound retained directions.
#define HTTP_CONTINUATION_TTL_NS (120ULL * 1000000000)

// Stable diagnostic indexes. Misses include non-HTTP candidates, not just loss.
enum http_continuation_stat {
    HTTP_CONTINUATION_MISS = 0,
    HTTP_CONTINUATION_EXPIRED = 1,
    HTTP_CONTINUATION_BUDGET_EXHAUSTED = 2,
    HTTP_CONTINUATION_STORE_FAILED = 3,
    HTTP_CONTINUATION_STAT_COUNT = 4,
};

#define MSG_PEEK 0x02

// Packet structs:
struct packet_buffer {
    int sockfd;
    __u64 buf;
    size_t len;
};

struct http_continuation_key {
    __u64 socket_inode;
    __u8 is_rx;
    __u8 _pad[7];
};

struct http_continuation {
    __u64 expires_at_ns;
    __u32 remaining_bytes;
    __u8 type;
};

struct packet_msg {
    int32_t fd;
    uint64_t iovec_ptr;  // user_msghdr
    size_t iovlen;
};

struct packet_mmsg {
    int32_t fd;
    uint32_t msg_count;
    struct packet_msg msgs[MAX_MSG_COUNT];
};

struct httpevent {    
    gadget_timestamp timestamp_raw;
    struct gadget_process proc;

    struct gadget_l4endpoint_t src;
    struct gadget_l4endpoint_t dst;

    u8   type;
    u32  sock_fd;
    u16  buf_len;
    u8   buf[MAX_DATAEVENT_BUFFER];
    u8   syscall[MAX_SYSCALL];
    
    // Add socket inode to uniquely identify sockets across processes
    __u64 socket_inode;
};
