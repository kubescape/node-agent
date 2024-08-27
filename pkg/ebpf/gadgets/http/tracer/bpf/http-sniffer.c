#include "sniffer_strcuts.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

typedef unsigned short int sa_family_t;

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct pre_accept_args);
} pre_accept_args_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct pre_connect_args);
} active_connections_args_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct active_connection_info);
} accepted_sockets_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct packet_buffer);
} buffer_packets SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct packet_msg);
} msg_packets SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct httpevent);
} event_data SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[PACKET_CHUNK_SIZE]);
} empty_char SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} debug_events SEC(".maps");

const struct httpevent *unusedevent __attribute__((unused));
const struct debug_event *unusedevent2 __attribute__((unused));

static __always_inline bool should_discard()
{
    struct task_struct *current_task = (struct task_struct*)bpf_get_current_task();
    if (!current_task) {
        return 1;
    }
     u64 mntns_id = BPF_CORE_READ(current_task, nsproxy, mnt_ns, ns.inum);
    if (gadget_should_discard_mntns_id(mntns_id)) {
        return 1;
    }
}

static __always_inline __u64 generate_unique_connection_id(__u64 pid_tgid, __u32 sockfd)
{
    __u32 tgid = pid_tgid >> 32; // Correctly extract TGID from upper 32 bits
    return ((__u64)tgid << 32) | sockfd;
}

static __always_inline void get_namespace_ids(u64 *mnt_ns_id, u64 *net_ns_id)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task)
    {
        struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
        if (nsproxy)
        {
            struct mnt_namespace *mnt_ns = BPF_CORE_READ(nsproxy, mnt_ns);
            struct net *net_ns = BPF_CORE_READ(nsproxy, net_ns);
            if (mnt_ns)
            {
                *mnt_ns_id = BPF_CORE_READ(mnt_ns, ns.inum);
            }
            if (net_ns)
            {
                *net_ns_id = BPF_CORE_READ(net_ns, ns.inum);
            }
        }
    }
}

static __always_inline int send_sock_debug_event(struct trace_event_raw_sys_enter *ctx,
                                                 const char *msg,
                                                 __u32 sockfd,
                                                 struct sockaddr_in *addr)
{
    struct debug_event event = {};

    event.sockfd = sockfd;
    if (addr)
    {
        bpf_probe_read_user(&event.addr, sizeof(event.addr), addr);
    }

    bpf_probe_read_kernel_str(event.message, sizeof(event.message), msg);

    bpf_perf_event_output(ctx, &debug_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

static __always_inline bool check_msg_peek(__u32 flags)  {
        return flags & MSG_PEEK;
}

    static __always_inline int populate_httpevent(struct httpevent *event)
{
    if (!event)
        return -1;

    u64 mnt_ns_id = 0;
    u64 net_ns_id = 0;
    get_namespace_ids(&mnt_ns_id, &net_ns_id);

    event->netns = net_ns_id;
    event->mntns_id = mnt_ns_id;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;

    u64 uid_gid = bpf_get_current_uid_gid();
    event->uid = uid_gid & 0xFFFFFFFF;
    event->gid = uid_gid >> 32;

    return 0;
}

static __always_inline void enrich_ip_port(struct trace_event_raw_sys_enter *ctx, __u32 sockfd, struct httpevent *event)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u64 unique_connection_id = generate_unique_connection_id(id, sockfd);
    struct active_connection_info *conn_info = bpf_map_lookup_elem(&accepted_sockets_map, &unique_connection_id);
    if (conn_info)
    {
        event->other_ip = conn_info->addr.sin_addr.s_addr;
        event->other_port = bpf_ntohs(conn_info->addr.sin_port);
    }
}

static void inline enter_connect(struct trace_event_raw_sys_enter *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct pre_connect_args connect_args;
    connect_args.sockfd = (int)ctx->args[0]; // socketfd to connect with
    bpf_probe_read_user(&connect_args.addr, sizeof(connect_args.addr), (void *)ctx->args[1]);
    bpf_map_update_elem(&active_connections_args_map, &id, &connect_args, BPF_ANY);
}

static void inline exit_connect(struct trace_event_raw_sys_exit *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct active_connection_info conn_info;

    if (ctx->ret == 0)
    {
        struct pre_connect_args *args = bpf_map_lookup_elem(&active_connections_args_map, &id);

        if (args)
        {
            __u32 sockfd = (__u32)args->sockfd; // For connect, we stored the sockfd earlier
            __u64 unique_connection_id = generate_unique_connection_id(id, sockfd);
            conn_info.sockfd = sockfd;
            bpf_probe_read_kernel(&conn_info.addr, sizeof(conn_info.addr), &args->addr);
            bpf_map_update_elem(&accepted_sockets_map, &unique_connection_id, &conn_info, BPF_ANY);
        }
    }

    bpf_map_delete_elem(&active_connections_args_map, &id);
}

static void inline enter_accept(struct trace_event_raw_sys_enter *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct pre_accept_args accept_args;
    accept_args.addr_ptr = (uint64_t)ctx->args[1];
    bpf_map_update_elem(&pre_accept_args_map, &id, &accept_args, BPF_ANY);
}

static void inline exit_accept(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct active_connection_info conn_info;
    if (ctx->ret >= 0)
    {
        __u32 sockfd = (__u32)ctx->ret; // new socket for accepted connection
        struct pre_accept_args *args = bpf_map_lookup_elem(&pre_accept_args_map, &pid_tgid);
        if (args)
        {
            __u64 unique_connection_id = generate_unique_connection_id(pid_tgid, sockfd);
            conn_info.sockfd = sockfd;
            bpf_probe_read_user(&conn_info.addr, sizeof(conn_info.addr), (void *)args->addr_ptr);
            bpf_map_update_elem(&accepted_sockets_map, &unique_connection_id, &conn_info, BPF_ANY);
            // send_sock_debug_event(ctx, "debug",  sockfd, (void*)args->addr_ptr);
        }
    }
    bpf_map_delete_elem(&pre_accept_args_map, &pid_tgid);
}

// Store the arguments of the receive syscalls in a map
static void inline pre_receive_syscalls(struct trace_event_raw_sys_enter *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 sockfd = (__u32)ctx->args[0]; // For read, recv, recvfrom, write, send, sendto, sockfd is the first argument
    __u64 unique_connection_id = generate_unique_connection_id(id, sockfd);
    struct active_connection_info *conn_info = bpf_map_lookup_elem(&accepted_sockets_map, &unique_connection_id);
    if (conn_info)
    {
        struct packet_buffer packet;
        packet.sockfd = sockfd;
        packet.buf = (__u64)ctx->args[1];
        packet.len = ctx->args[2];
        bpf_map_update_elem(&buffer_packets, &id, &packet, BPF_ANY);
    }
}

static __always_inline int get_http_type(struct trace_event_raw_sys_exit *ctx, void *data, int size)
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

static __always_inline int process_packet(struct trace_event_raw_sys_exit *ctx, char *syscall)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct packet_buffer *packet = bpf_map_lookup_elem(&buffer_packets, &id);
    if (!packet)
        return 0;

    if (ctx->ret <= 0)
        return 0;

    __u32 total_size = (__u32)ctx->ret;

    __u32 key = 0;

    char *buf = bpf_map_lookup_elem(&empty_char, &key);
    if (!buf)
        return 0;

    int read_size = bpf_probe_read_user(buf, MIN(packet->len, PACKET_CHUNK_SIZE), (void *)packet->buf);
    if (read_size < 0)
        return 0;
    int type = get_http_type(ctx, buf, MIN(total_size, PACKET_CHUNK_SIZE));
    if (!type)
        return 0;

    __u32 zero = 0;
    struct httpevent *dataevent = bpf_map_lookup_elem(&event_data, &zero);
    if (!dataevent)
        return 0;

    populate_httpevent(dataevent);
    enrich_ip_port(ctx, packet->sockfd, dataevent);
    dataevent->type = type;
    dataevent->sock_fd = packet->sockfd;

    bpf_probe_read(&dataevent->syscall, sizeof(syscall), syscall);
    bpf_probe_read_user(&dataevent->buf, MIN(total_size, MAX_DATAEVENT_BUFFER), (void *)packet->buf);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, dataevent, sizeof(*dataevent));
    bpf_map_delete_elem(&buffer_packets, &id);
    return 0;
}

static __always_inline int pre_process_msg(struct trace_event_raw_sys_enter *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 sockfd = (__u32)ctx->args[0]; // For sendmsg and recvmsg, sockfd is the first argument
    __u64 unique_connection_id = generate_unique_connection_id(id, sockfd);
    struct active_connection_info *conn_info = bpf_map_lookup_elem(&accepted_sockets_map, &unique_connection_id);
    if (conn_info)
    {
        struct packet_msg write_args = {};
        write_args.fd = sockfd;

        struct user_msghdr msghdr;
        if (bpf_probe_read_user(&msghdr, sizeof(msghdr), (void *)ctx->args[1]) != 0)
        {
            return 0;
        }

        write_args.iovec_ptr = (uint64_t)(msghdr.msg_iov);
        write_args.iovlen = msghdr.msg_iovlen;
        bpf_map_update_elem(&msg_packets, &id, &write_args, BPF_ANY);
    }
    return 0;
}

static __always_inline int pre_process_iovec(struct trace_event_raw_sys_enter *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 sockfd = (__u32)ctx->args[0]; // For writev and readv, sockfd is the first argument
    __u64 unique_connection_id = generate_unique_connection_id(id, sockfd);
    struct active_connection_info *conn_info = bpf_map_lookup_elem(&accepted_sockets_map, &unique_connection_id);
    if (conn_info)
    {
        struct packet_msg write_args = {};
        write_args.fd = sockfd;
        write_args.iovec_ptr = (__u64)ctx->args[1];
        write_args.iovlen = (__u64)ctx->args[2];
        bpf_map_update_elem(&msg_packets, &id, &write_args, BPF_ANY);
    }
    return 0;
}

static __always_inline int process_msg(struct trace_event_raw_sys_exit *ctx, char *syscall)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct packet_msg *msg = bpf_map_lookup_elem(&msg_packets, &id);
    if (!msg)
        return 0;

    // Loop through iovec structures
    for (__u64 i = 0; i < msg->iovlen && i < 28; i++)
    {
        struct iovec iov;
        int ret = bpf_probe_read_user(&iov, sizeof(iov), (void *)(msg->iovec_ptr + i * sizeof(struct iovec)));
        if (ret < 0)
            break;

        __u64 seg_len = iov.iov_len;
        if (seg_len > PACKET_CHUNK_SIZE)
            seg_len = PACKET_CHUNK_SIZE;

        char buffer[PACKET_CHUNK_SIZE];
        ret = bpf_probe_read_user(buffer, seg_len, iov.iov_base);
        if (ret < 0)
            break;

        // Check if this segment is an HTTP message
        int type = get_http_type(ctx, buffer, seg_len);
        if (type)
        {
            __u32 zero = 0;
            struct httpevent *dataevent = bpf_map_lookup_elem(&event_data, &zero);
            if (!dataevent)
                continue;

            populate_httpevent(dataevent);
            enrich_ip_port(ctx, msg->fd, dataevent);
            dataevent->type = type;
            dataevent->sock_fd = msg->fd;

            __u64 copy_len = seg_len;
            if (copy_len > MAX_DATAEVENT_BUFFER)
                copy_len = MAX_DATAEVENT_BUFFER;

            bpf_probe_read(dataevent->buf, copy_len, buffer);
            bpf_probe_read(&dataevent->syscall, MIN(sizeof(syscall), MAX_SYSCALL), syscall);
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, dataevent, sizeof(*dataevent));
        }
    }
    bpf_map_delete_elem(&msg_packets, &id);
}

SEC("tracepoint/syscalls/sys_enter_accept")
int sys_enter_accept(struct trace_event_raw_sys_enter *ctx)
{
    if (should_discard()) return 0;
    enter_accept(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int sys_exit_accept(struct trace_event_raw_sys_exit *ctx)
{
    if (should_discard()) return 0;
    exit_accept(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int sys_enter_accept4(struct trace_event_raw_sys_enter *ctx)
{
    if (should_discard()) return 0;
    enter_accept(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int sys_exit_accept4(struct trace_event_raw_sys_exit *ctx)
{
    if (should_discard()) return 0;
    exit_accept(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int sys_enter_close(struct trace_event_raw_sys_enter *ctx)
{
    if (should_discard()) return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 sockfd = (__u32)ctx->args[0];
    __u64 unique_connection_id = generate_unique_connection_id(pid_tgid, sockfd);
    bpf_map_delete_elem(&accepted_sockets_map, &unique_connection_id);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
    if (should_discard()) return 0;
    pre_receive_syscalls(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
    if (should_discard()) return 0;
    process_packet(ctx, "read");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int sys_enter_recvfrom(struct trace_event_raw_sys_enter *ctx)
{
    if (should_discard()) return 0;
    if (check_msg_peek(ctx->args[3])) return 0;
    pre_receive_syscalls(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int sys_exit_recvfrom(struct trace_event_raw_sys_exit *ctx)
{
    if (should_discard()) return 0;
    process_packet(ctx, "recvfrom");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int syscall__probe_entry_write(struct trace_event_raw_sys_enter *ctx)
{
    if (should_discard()) return 0;
    pre_receive_syscalls(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int syscall__probe_ret_write(struct trace_event_raw_sys_exit *ctx)
{
    if (should_discard()) return 0;
    process_packet(ctx, "write");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int syscall__probe_entry_sendto(struct trace_event_raw_sys_enter *ctx)
{
    if (should_discard()) return 0;
    pre_receive_syscalls(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int syscall__probe_ret_sendto(struct trace_event_raw_sys_exit *ctx)
{
    if (should_discard()) return 0;
    process_packet(ctx, "sendto");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int syscall__probe_entry_connect(struct trace_event_raw_sys_enter *ctx)
{
    if (should_discard()) return 0;
    enter_connect(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int syscall__probe_ret_connect(struct trace_event_raw_sys_exit *ctx)
{
    if (should_discard()) return 0;
    exit_connect(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int syscall__probe_entry_sendmsg(struct trace_event_raw_sys_enter *ctx)
{
    if (should_discard()) return 0;
    pre_process_msg(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendmsg")
int syscall__probe_ret_sendmsg(struct trace_event_raw_sys_exit *ctx)
{
    if (should_discard()) return 0;
    process_msg(ctx, "sendmsg");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int syscall__probe_entry_recvmsg(struct trace_event_raw_sys_enter *ctx)
{
    if (should_discard()) return 0;
    if (check_msg_peek(ctx->args[2])) return 0;
    pre_process_msg(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvmsg")
int syscall__probe_ret_recvmsg(struct trace_event_raw_sys_exit *ctx)
{
    if (should_discard()) return 0;
    process_msg(ctx, "recvmsg");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int syscall__probe_entry_writev(struct trace_event_raw_sys_enter *ctx)
{
    if (should_discard()) return 0;
    pre_process_iovec(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_writev")
int syscall__probe_ret_writev(struct trace_event_raw_sys_exit *ctx)
{
    if (should_discard()) return 0;
    process_msg(ctx, "writev");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readv")
int syscall__probe_entry_readv(struct trace_event_raw_sys_enter *ctx)
{
    if (should_discard()) return 0;
    pre_process_iovec(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_readv")
int syscall__probe_ret_readv(struct trace_event_raw_sys_exit *ctx)
{
    if (should_discard()) return 0;
    process_msg(ctx, "readv");
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";