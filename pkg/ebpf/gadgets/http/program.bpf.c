// Kernel types definitions
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Inspektor Gadget buffer
#include <gadget/buffer.h>

// Helpers to handle common data
#include <gadget/common.h>

// Inspektor Gadget macros
#include <gadget/macros.h>

// Inspektor Gadget filtering
#include <gadget/filter.h>

// Inspektor Gadget types
#include <gadget/types.h>

// Inspektor Gadget mntns
#include <gadget/mntns.h>

#include "program.h"

// events is the name of the buffer map and 1024 * 256 (256KB) is its size.
GADGET_TRACER_MAP(events, 1024 * 256);

// Define a tracer
GADGET_TRACER(http, events, httpevent);

// Used to allocate http event
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct httpevent);
} event_data SEC(".maps");

// Used to store the buffer of packets 
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct packet_buffer);
} buffer_packets SEC(".maps");

// Used to store the buffer of messages of messages type
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct packet_msg);
} msg_packets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, u8[MAX_DATAEVENT_BUFFER]);
} empty_buffer SEC(".maps");

static __always_inline __u64 min_size(__u64 a, __u64 b) {
    return a < b ? a : b;
}

static __always_inline struct httpevent *get_dataevent()
{
    __u32 zero = 0;
    struct httpevent *dataevent = bpf_map_lookup_elem(&event_data, &zero);
    if (!dataevent)
        return NULL;

    u8 *empty = bpf_map_lookup_elem(&empty_buffer, &zero);
    if (empty) {
        bpf_probe_read(dataevent->buf, sizeof(dataevent->buf), empty);
        bpf_probe_read(dataevent->syscall, sizeof(dataevent->syscall), empty);
    }

    return dataevent;
}

// Get inode number for a socket file descriptor
static __always_inline int get_socket_inode(__u32 sockfd, __u64 *inode) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return -1;

    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files)
        return -1;

    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt)
        return -1;

    struct file **fd_array = BPF_CORE_READ(fdt, fd);
    if (!fd_array)
        return -1;

    struct file *file;
    void *ptr;
    bpf_probe_read(&ptr, sizeof(ptr), &fd_array[sockfd]);
    file = ptr;
    if (!file)
        return -1;

    struct inode *inode_ptr = BPF_CORE_READ(file, f_inode);
    if (!inode_ptr)
        return -1;

    *inode = BPF_CORE_READ(inode_ptr, i_ino);
    return 0;
}

static __always_inline bool is_msg_peek(__u32 flags)
{
    return flags & MSG_PEEK;
}


static __always_inline int populate_httpevent(struct httpevent *event, __u32 sockfd)
{
    if (!event)
        return -1;

    // Populate the process data into the event.
    gadget_process_populate(&event->proc);
    
    // Get and store socket inode
    __u64 socket_inode = 0;
    if (get_socket_inode(sockfd, &socket_inode) == 0) {
        event->socket_inode = socket_inode;
    } else {
        event->socket_inode = 0;
    }

    return 0;
}

static __always_inline int get_http_type(struct syscall_trace_exit *ctx, void *data, int size)
{
    // Check for common HTTP methods
    const char *http_methods[] = {"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "TRACE ", "CONNECT "};
    int num_methods = sizeof(http_methods) / sizeof(http_methods[0]);

    if (size < 4)
    {
        return 0;
    }

    for (int i = 0; i < num_methods; i++)
    {

        if (__builtin_memcmp(data, http_methods[i], 4) == 0)
        {
            return EVENT_TYPE_REQUEST;
        }
    }

    if (__builtin_memcmp(data, "HTTP", 4) == 0)
    {
        return EVENT_TYPE_RESPONSE;
    }

    return 0;
}

// Store the arguments of the receive syscalls in a map
static void inline pre_receive_syscalls(struct syscall_trace_enter *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 sockfd = (__u32)ctx->args[0]; // For read, recv, recvfrom, write, send, sendto, sockfd is the first argument
    
    // No need to check if socket is being tracked - track all sockets
    struct packet_buffer packet = {};
    packet.sockfd = sockfd;
    packet.buf = (__u64)ctx->args[1];
    packet.len = ctx->args[2];
    bpf_map_update_elem(&buffer_packets, &id, &packet, BPF_ANY);
}

static __always_inline int process_packet(struct syscall_trace_exit *ctx, char *syscall)
{
    __u64 id = bpf_get_current_pid_tgid();
    char buf[PACKET_CHUNK_SIZE] = {0};
    __u32 total_size = (__u32)ctx->ret;

    struct packet_buffer *packet = bpf_map_lookup_elem(&buffer_packets, &id);
    if (!packet)
        return 0;

    if (ctx->ret <= 0)
        return 0;

    if (total_size < 1)
        return 0;

    if (packet->len < 1)
        return 0;

    int read_size = bpf_probe_read_user(buf, min_size(packet->len, PACKET_CHUNK_SIZE), (void *)packet->buf);
    if (read_size < 0)
        return 0;

    int type = get_http_type(ctx, buf, min_size(total_size, PACKET_CHUNK_SIZE));
    if (!type)
        return 0;

    struct httpevent *dataevent = get_dataevent();
    if (!dataevent)
        return 0;

    // Populate event with socket inode for tracking
    populate_httpevent(dataevent, packet->sockfd);
        
    dataevent->type = type;
    dataevent->sock_fd = packet->sockfd;

    bpf_probe_read_str(&dataevent->syscall, sizeof(dataevent->syscall), syscall);
    bpf_probe_read_user(&dataevent->buf, min_size(total_size, MAX_DATAEVENT_BUFFER), (void *)packet->buf);

    // Use gadget_output_buf to copy the event to the map
    gadget_output_buf(ctx, &events, dataevent, sizeof(*dataevent)); // TODO: check if this is correct

    bpf_map_delete_elem(&buffer_packets, &id);
    return 0;
}

static __always_inline int pre_process_msg(struct syscall_trace_enter *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 sockfd = (__u32)ctx->args[0]; // For sendmsg and recvmsg, sockfd is the first argument
    
    // No need to check if socket is being tracked - track all sockets
    struct packet_msg write_args = {};
    write_args.fd = sockfd;

    struct user_msghdr msghdr = {};
    if (bpf_probe_read_user(&msghdr, sizeof(msghdr), (void *)ctx->args[1]) != 0)
    {
        return 0;
    }

    write_args.iovec_ptr = (uint64_t)(msghdr.msg_iov);
    write_args.iovlen = msghdr.msg_iovlen;
    bpf_map_update_elem(&msg_packets, &id, &write_args, BPF_ANY);
    return 0;
}

static __always_inline int pre_process_iovec(struct syscall_trace_enter *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 sockfd = (__u32)ctx->args[0]; // For writev and readv, sockfd is the first argument
    
    // No need to check if socket is being tracked - track all sockets
    struct packet_msg write_args = {};
    write_args.fd = sockfd;
    write_args.iovec_ptr = (__u64)ctx->args[1];
    write_args.iovlen = (__u64)ctx->args[2];
    bpf_map_update_elem(&msg_packets, &id, &write_args, BPF_ANY);
    return 0;
}

static __always_inline int process_msg(struct syscall_trace_exit *ctx, char *syscall)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct packet_msg *msg = bpf_map_lookup_elem(&msg_packets, &id);
    if (!msg)
        return 0;

    for (__u64 i = 0; i < msg->iovlen && i < 28; i++)
    {
        struct iovec iov = {};
        int ret = bpf_probe_read_user(&iov, sizeof(iov), (void *)(msg->iovec_ptr + i * sizeof(struct iovec)));
        if (ret < 0)
            break;

        __u64 seg_len = iov.iov_len;
        if (seg_len > PACKET_CHUNK_SIZE)
            seg_len = PACKET_CHUNK_SIZE;

        char buffer[PACKET_CHUNK_SIZE] = {0};
        ret = bpf_probe_read_user(buffer, seg_len, iov.iov_base);
        if (ret < 0)
            break;

        int type = get_http_type(ctx, buffer, seg_len);
        if (type)
        {
            seg_len = iov.iov_len;

            // Get the event from the map
            struct httpevent *dataevent = get_dataevent();
            if (!dataevent)
                return 0;

            // Populate event with socket inode for tracking
            populate_httpevent(dataevent, msg->fd);
            
            dataevent->type = type;
            dataevent->sock_fd = msg->fd;
            
            __u64 copy_len = seg_len;
            if (copy_len > MAX_DATAEVENT_BUFFER)
                copy_len = MAX_DATAEVENT_BUFFER;

            bpf_probe_read_user(&dataevent->buf, copy_len, iov.iov_base);
            bpf_probe_read_str(&dataevent->syscall, sizeof(dataevent->syscall), syscall);

            // Use gadget_output_buf to copy the event to the map
            gadget_output_buf(ctx, &events, dataevent, sizeof(*dataevent)); // TODO: check if this is correct
            break;
        }
    }

    bpf_map_delete_elem(&msg_packets, &id);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct syscall_trace_enter *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }

    pre_receive_syscalls(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int sys_exit_read(struct syscall_trace_exit *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }
    process_packet(ctx, "read");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int sys_enter_recvfrom(struct syscall_trace_enter *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }

    if (is_msg_peek(ctx->args[3]))
        return 0;
    pre_receive_syscalls(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int sys_exit_recvfrom(struct syscall_trace_exit *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }

    process_packet(ctx, "recvfrom");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int syscall__probe_entry_write(struct syscall_trace_enter *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }

    pre_receive_syscalls(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int syscall__probe_ret_write(struct syscall_trace_exit *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }

    process_packet(ctx, "write");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int syscall__probe_entry_sendto(struct syscall_trace_enter *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }

    pre_receive_syscalls(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int syscall__probe_ret_sendto(struct syscall_trace_exit *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }

    process_packet(ctx, "sendto");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int syscall__probe_entry_sendmsg(struct syscall_trace_enter *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }

    pre_process_msg(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendmsg")
int syscall__probe_ret_sendmsg(struct syscall_trace_exit *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }

    process_msg(ctx, "sendmsg");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int syscall__probe_entry_recvmsg(struct syscall_trace_enter *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }

    if (is_msg_peek(ctx->args[2]))
        return 0;
    pre_process_msg(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvmsg")
int syscall__probe_ret_recvmsg(struct syscall_trace_exit *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }

    process_msg(ctx, "recvmsg");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int syscall__probe_entry_writev(struct syscall_trace_enter *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }

    pre_process_iovec(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_writev")
int syscall__probe_ret_writev(struct syscall_trace_exit *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }

    process_msg(ctx, "writev");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readv")
int syscall__probe_entry_readv(struct syscall_trace_enter *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }
    pre_process_iovec(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_readv")
int syscall__probe_ret_readv(struct syscall_trace_exit *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }
    process_msg(ctx, "readv");
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
