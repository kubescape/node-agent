#pragma once

#include <gadget/types.h>

#define EVENT_TYPE_REQUEST 2
#define EVENT_TYPE_RESPONSE 3

#define MAX_PACKET_SIZE 200
#define PACKET_CHUNK_SIZE 200
#define MAX_DATAEVENT_BUFFER 4096
#define MAX_SYSCALL 128
#define MAX_MSG_COUNT 20

#define MSG_PEEK 0x02

// Packet structs:
struct packet_buffer {
    int sockfd;
    __u64 buf;
    size_t len;
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
    u8   buf[MAX_DATAEVENT_BUFFER];
    u8   syscall[MAX_SYSCALL];
    
    // Add socket inode to uniquely identify sockets across processes
    __u64 socket_inode;
};
