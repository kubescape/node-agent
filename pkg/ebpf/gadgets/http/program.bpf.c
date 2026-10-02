// Kernel types definitions
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// The perf-buffer fallback allocates this many bytes per CPU event slot. Keep
// it above the 16 KiB httpevent ABI before gadget/buffer.h consumes the macro.
#define GADGET_MAX_EVENT_SIZE (20 * 1024)

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

// A 1 MiB ring preserves approximately the pre-16-KiB event burst capacity.
GADGET_TRACER_MAP(events, 1024 * 1024);

// Define a tracer
GADGET_TRACER(http, events, httpevent);

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

// Tracks an HTTP request/response direction after its start line has been
// observed. The next write/read frequently contains only body bytes, which do
// not start with an HTTP method or status line and therefore cannot be
// classified independently.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct http_continuation_key);
    __type(value, struct http_continuation);
} http_continuations SEC(".maps");

// Per-CPU diagnostics avoid cross-CPU contention on the syscall hot path.
// Readers sum CPU slots for each reason: cap, ring reservation, user read.
enum http_capture_loss { HTTP_LOSS_LIMIT, HTTP_LOSS_RESERVE, HTTP_LOSS_READ, HTTP_LOSS_COUNT };
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, HTTP_LOSS_COUNT);
    __type(key, __u32);
    __type(value, __u64);
} capture_loss SEC(".maps");
// Diagnostic-only per-CPU counters; readers sum CPU slots per reason.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, HTTP_CONTINUATION_STAT_COUNT);
    __type(key, __u32);
    __type(value, __u64);
} continuation_stats SEC(".maps");

static __always_inline __u64 min_size(__u64 a, __u64 b) {
    return a < b ? a : b;
}

static __always_inline bool is_msg_peek(__u32 flags)
{
    return flags & MSG_PEEK;
}

static __always_inline __u64 get_socket_inode(__u32 sockfd)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files)
        return 0;

    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt)
        return 0;

    struct file **fd_array = BPF_CORE_READ(fdt, fd);
    if (!fd_array)
        return 0;

    struct file *file_ptr;
    bpf_probe_read(&file_ptr, sizeof(file_ptr), &fd_array[sockfd]);
    if (!file_ptr)
        return 0;

    struct inode *inode_ptr = BPF_CORE_READ(file_ptr, f_inode);
    if (!inode_ptr)
        return 0;

    return BPF_CORE_READ(inode_ptr, i_ino);
}

// Metadata is constant throughout one syscall. Resolve it once rather than
// repeating the process/socket walk for every captured payload chunk.
struct http_metadata {
    gadget_timestamp timestamp_raw;
    struct gadget_process proc;
    struct gadget_l4endpoint_t src;
    struct gadget_l4endpoint_t dst;
    __u64 socket_inode;
};

// is_rx: true if this is an inbound packet (read/recv), false if outbound (write/send)
static __noinline int populate_http_metadata(struct http_metadata *event, __u32 sockfd, bool is_rx)
{
    if (!event)
        return -1;

    // Populate the process data into the event.
    gadget_process_populate(&event->proc);

    // Initialize defaults
    event->socket_inode = 0;

    // Get socket file descriptor and extract both inode and socket info in one pass
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        goto out;

    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files)
        goto out;

    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt)
        goto out;

    struct file **fd_array = BPF_CORE_READ(fdt, fd);
    if (!fd_array)
        goto out;

    struct file *file_ptr;
    bpf_probe_read(&file_ptr, sizeof(file_ptr), &fd_array[sockfd]);
    if (!file_ptr)
        goto out;

    // Get socket inode from file->f_inode->i_ino
    event->socket_inode = get_socket_inode(sockfd);

    // Get socket from file->private_data
    struct socket *sock = BPF_CORE_READ(file_ptr, private_data);
    if (!sock)
        goto out;

    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (sk) {
        // Get raw values from the socket
        // skc_num is local port (host endian usually, but we enforce ntohs to be safe)
        // skc_rcv_saddr is local IP
        // skc_dport is remote port (network endian)
        // skc_daddr is remote IP
        
        __u16 local_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
        __u32 local_addr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        
        __u16 remote_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
        __u32 remote_addr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

        if (is_rx) {
            // INBOUND: 
            // Source = Remote Peer
            // Dest   = Local Machine
            event->src.port = remote_port;
            event->src.addr_raw.v4 = remote_addr;
            
            event->dst.port = local_port;
            event->dst.addr_raw.v4 = local_addr;
        } else {
            // OUTBOUND:
            // Source = Local Machine
            // Dest   = Remote Peer
            event->src.port = local_port;
            event->src.addr_raw.v4 = local_addr;
            
            event->dst.port = remote_port;
            event->dst.addr_raw.v4 = remote_addr;
        }

        event->src.version = 4;
        event->dst.version = 4;
    }

out:
    event->timestamp_raw = bpf_ktime_get_boot_ns();

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

static __always_inline void count_continuation_stat(__u32 reason)
{
    __u64 *counter = bpf_map_lookup_elem(&continuation_stats, &reason);
    if (counter)
        (*counter)++;
}

// resolve_http_type recognizes a message start or continues a recently seen
// message on the same socket direction. Userspace owns HTTP framing and drops
// data outside its own message boundary; this map only prevents body-only
// syscalls from being discarded before userspace can see them.
static __always_inline int resolve_http_type(struct syscall_trace_exit *ctx, __u32 sockfd,
                                              bool is_rx, void *data, int size,
                                              __u32 total_size)
{
    int type = get_http_type(ctx, data, size);
    __u64 socket_inode = get_socket_inode(sockfd);
    if (!socket_inode)
        return type;

    struct http_continuation_key key = {
        .socket_inode = socket_inode,
        .is_rx = is_rx,
    };
    __u64 now = bpf_ktime_get_boot_ns();

    if (type) {
        struct http_continuation continuation = {
            .expires_at_ns = now + HTTP_CONTINUATION_TTL_NS,
            .remaining_bytes = HTTP_CONTINUATION_MAX_BYTES,
            .type = type,
        };
        if (total_size >= continuation.remaining_bytes) {
            count_continuation_stat(HTTP_CONTINUATION_BUDGET_EXHAUSTED);
            bpf_map_delete_elem(&http_continuations, &key);
        } else {
            continuation.remaining_bytes -= total_size;
            if (bpf_map_update_elem(&http_continuations, &key, &continuation, BPF_ANY))
                count_continuation_stat(HTTP_CONTINUATION_STORE_FAILED);
        }
        return type;
    }

    struct http_continuation *continuation = bpf_map_lookup_elem(&http_continuations, &key);
    if (!continuation) {
        count_continuation_stat(HTTP_CONTINUATION_MISS);
        return 0;
    }
    if (now > continuation->expires_at_ns) {
        count_continuation_stat(HTTP_CONTINUATION_EXPIRED);
        bpf_map_delete_elem(&http_continuations, &key);
        return 0;
    }
    if (total_size > continuation->remaining_bytes) {
        count_continuation_stat(HTTP_CONTINUATION_BUDGET_EXHAUSTED);
        bpf_map_delete_elem(&http_continuations, &key);
        return 0;
    }

    // Forward the last bytes inside the budget before retiring the direction.
    int continuation_type = continuation->type;
    if (total_size == continuation->remaining_bytes) {
        count_continuation_stat(HTTP_CONTINUATION_BUDGET_EXHAUSTED);
        bpf_map_delete_elem(&http_continuations, &key);
        return continuation_type;
    }
    continuation->remaining_bytes -= total_size;
    // This is an idle timeout, not an absolute deadline: a streaming HTTP
    // response can legitimately run longer than the timeout while continuing
    // to deliver body chunks.
    continuation->expires_at_ns = now + HTTP_CONTINUATION_TTL_NS;
    return continuation->type;
}

// A failed chunk must not be followed by later bytes from this syscall or by
// body-only continuations. The unchanged event ABI has no offset/loss marker;
// userspace can still only recognize the incomplete body when it closes it.
static __always_inline void capture_failed(__u32 sockfd, bool is_rx, __u32 reason)
{
    struct http_continuation_key key = {
        .socket_inode = get_socket_inode(sockfd),
        .is_rx = is_rx,
    };
    bpf_map_delete_elem(&http_continuations, &key);
    __u64 *count = bpf_map_lookup_elem(&capture_loss, &reason);
    if (count)
        (*count)++;
}

static __always_inline void capture_read_failed(__u32 sockfd, bool is_rx, bool tracked)
{
    struct http_continuation_key key = {
        .socket_inode = get_socket_inode(sockfd),
        .is_rx = is_rx,
    };
    if (tracked || bpf_map_lookup_elem(&http_continuations, &key))
        capture_failed(sockfd, is_rx, HTTP_LOSS_READ);
}

// Share a total byte budget across all iovecs; a large vector count must not
// multiply the per-syscall work bound. Classify and charge continuation bytes
// once at the caller, not once per chunk.
struct payload_args {
    char syscall[MAX_SYSCALL];
    __u32 sockfd;
    int type;
    bool is_rx;
    struct http_metadata meta;
    __u64 remaining, actual_len, offset, base;
    __u32 index, captured, buffered;
};

// Syscall tracepoints execute without preemption. Keep the per-call metadata
// off the BPF stack so vector traversal stays within the 512-byte stack limit.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct payload_args);
} payload_scratch SEC(".maps");

static __always_inline struct payload_args *payload_context(char *syscall, __u32 sockfd, bool is_rx)
{
    __u32 zero = 0;
    struct payload_args *args = bpf_map_lookup_elem(&payload_scratch, &zero);
    if (!args)
        return 0;
    __builtin_memset(args, 0, sizeof(*args));
    args->sockfd = sockfd;
    args->is_rx = is_rx;
    bpf_probe_read_str(args->syscall, sizeof(args->syscall), syscall);
    return args;
}

static __noinline int emit_chunk(struct syscall_trace_exit *ctx, struct payload_args *args,
                                 __u64 buf, __u32 size)
{
    // Give both the compiler and verifier an explicit event bound.
    if (size > MAX_DATAEVENT_BUFFER)
        return -1;
    struct httpevent *event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event) {
        capture_failed(args->sockfd, args->is_rx, HTTP_LOSS_RESERVE);
        return -1;
    }
    if (bpf_probe_read_user(event->buf, size, (void *)buf)) {
        gadget_discard_buf(event);
        capture_failed(args->sockfd, args->is_rx, HTTP_LOSS_READ);
        return -1;
    }
    event->timestamp_raw = args->meta.timestamp_raw;
    event->proc = args->meta.proc;
    event->src = args->meta.src;
    event->dst = args->meta.dst;
    event->socket_inode = args->meta.socket_inode;
    event->type = args->type;
    event->sock_fd = args->sockfd;
    event->buf_len = size;
    bpf_probe_read_str(event->syscall, sizeof(event->syscall), args->syscall);
    gadget_submit_buf(ctx, &events, event, sizeof(*event));
    return 0;
}

static __noinline int emit_payload(struct syscall_trace_exit *ctx, struct payload_args *args,
                                        const void *buf, __u64 len)
{
    __u64 offset = 0;
    #pragma unroll
    for (int i = 0; i < HTTP_MAX_CHUNKS; i++) {
        if (offset >= len)
            return 0;
        __u32 size = min_size(len - offset, MAX_DATAEVENT_BUFFER);
        if (emit_chunk(ctx, args, (__u64)buf + offset, size))
            return -1;
        offset += size;
    }
    if (offset < len) {
        capture_failed(args->sockfd, args->is_rx, HTTP_LOSS_LIMIT);
        return -1;
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

static __always_inline int process_packet(struct syscall_trace_exit *ctx, char *syscall, bool is_rx)
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
    if (read_size < 0) {
        capture_read_failed(packet->sockfd, is_rx, false);
        bpf_map_delete_elem(&buffer_packets, &id);
        return 0;
    }

    int type = resolve_http_type(ctx, packet->sockfd, is_rx, buf,
                                 min_size(total_size, PACKET_CHUNK_SIZE), total_size);
    if (!type)
        return 0;

    struct payload_args *args = payload_context(syscall, packet->sockfd, is_rx);
    if (args) {
        args->type = type;
        populate_http_metadata(&args->meta, args->sockfd, args->is_rx);
        emit_payload(ctx, args, (void *)packet->buf, total_size);
    }

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

    // A failed argument read must not leave a previous syscall available to
    // the exit probe. In particular, receive peeks intentionally skip entry.
    bpf_map_delete_elem(&msg_packets, &id);
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

// Keep the payload separate: a per-CPU map value cannot exceed 32 KiB.
// Independent verifier ranges need double storage, while logical writes use
// only the first 16 KiB, enforced by emit_iov_step.
struct http_aggregate {
    __u8 data[2 * MAX_DATAEVENT_BUFFER];
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct http_aggregate);
} aggregate_scratch SEC(".maps");

// Keep aggregation in per-CPU scratch rather than holding a ring
// reservation while walking descriptors. A read/reservation failure discards
// the incomplete aggregate; work limits flush the valid prefix before retiring.
static __noinline int flush_iov(struct syscall_trace_exit *ctx, struct payload_args *args)
{
    __u32 size = args->buffered;
    if (!size)
        return 0;
    if (size > MAX_DATAEVENT_BUFFER)
        return -1;
    __u32 zero = 0;
    struct http_aggregate *aggregate = bpf_map_lookup_elem(&aggregate_scratch, &zero);
    if (!aggregate) {
        capture_failed(args->sockfd, args->is_rx, HTTP_LOSS_READ);
        return -1;
    }
    struct httpevent *event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event) {
        capture_failed(args->sockfd, args->is_rx, HTTP_LOSS_RESERVE);
        return -1;
    }
    if (bpf_probe_read(event->buf, size, aggregate->data)) {
        gadget_discard_buf(event);
        capture_failed(args->sockfd, args->is_rx, HTTP_LOSS_READ);
        return -1;
    }
    event->timestamp_raw = args->meta.timestamp_raw;
    event->proc = args->meta.proc;
    event->src = args->meta.src;
    event->dst = args->meta.dst;
    event->socket_inode = args->meta.socket_inode;
    event->type = args->type;
    event->sock_fd = args->sockfd;
    event->buf_len = size;
    bpf_probe_read_str(event->syscall, sizeof(event->syscall), args->syscall);
    gadget_submit_buf(ctx, &events, event, sizeof(*event));
    args->buffered = 0;
    return 0;
}

// Each step consumes a descriptor or fills an aggregate. Return -1 on loss,
// zero on completion, or one when more bounded work remains.
static __noinline int emit_iov_step(struct syscall_trace_exit *ctx, struct payload_args *args,
                                    struct packet_msg *msg)
{
    if (args->offset == args->actual_len) {
        if (!args->remaining)
            return 0;
        __u32 index = args->index;
        if (index >= msg->iovlen || index >= 28) {
            if (flush_iov(ctx, args))
                return -1;
            capture_failed(msg->fd, args->is_rx, HTTP_LOSS_LIMIT);
            return -1;
        }
        struct iovec iov = {};
        if (bpf_probe_read_user(&iov, sizeof(iov), (void *)(msg->iovec_ptr + index * sizeof(iov)))) {
            capture_failed(msg->fd, args->is_rx, HTTP_LOSS_READ);
            return -1;
        }
        args->index = index + 1;
        args->actual_len = min_size(iov.iov_len, args->remaining);
        args->remaining -= args->actual_len;
        args->offset = 0;
        args->base = (__u64)iov.iov_base;
        if (!args->actual_len)
            return 1;
    }
    __u32 captured = args->captured;
    if (captured >= HTTP_MAX_CHUNKS * MAX_DATAEVENT_BUFFER) {
        if (flush_iov(ctx, args))
            return -1;
        capture_failed(msg->fd, args->is_rx, HTTP_LOSS_LIMIT);
        return -1;
    }
    __u64 buffered = args->buffered;
    if (buffered >= MAX_DATAEVENT_BUFFER)
        return -1;
    __u64 capacity = MAX_DATAEVENT_BUFFER - buffered;
    __u64 size = min_size(args->actual_len - args->offset, capacity);
    size = min_size(size, HTTP_MAX_CHUNKS * MAX_DATAEVENT_BUFFER - captured);
    // LLVM can otherwise fold away the explicit bounds below because min_size
    // already implies them in C. The verifier needs those checks after both
    // minima; this register barrier emits no instructions.
    asm volatile("" : "+r"(size), "+r"(capacity));
    // Check the helper's size itself in 64 bits. Checking a narrowed sum does
    // not bound this scalar on older verifiers (notably COS 121 / Linux 6.6).
    if (size > MAX_DATAEVENT_BUFFER || size > capacity)
        return -1;
    __u32 zero = 0;
    struct http_aggregate *aggregate = bpf_map_lookup_elem(&aggregate_scratch, &zero);
    if (!aggregate || bpf_probe_read_user(aggregate->data + buffered, size, (void *)(args->base + args->offset))) {
        capture_failed(msg->fd, args->is_rx, HTTP_LOSS_READ);
        return -1;
    }
    args->offset += size;
    args->captured = captured + size;
    args->buffered = buffered + size;
    if (args->buffered == MAX_DATAEVENT_BUFFER && flush_iov(ctx, args))
        return -1;
    return 1;
}

static __always_inline int process_msg(struct syscall_trace_exit *ctx, char *syscall, bool is_rx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct packet_msg *msg = bpf_map_lookup_elem(&msg_packets, &id);
    if (!msg)
        return 0;
    if (ctx->ret <= 0) {
        bpf_map_delete_elem(&msg_packets, &id);
        return 0;
    }

    // Classify once from the first transferred bytes, just like a scalar
    // syscall. Charge the aggregate successful return once, not each chunk.
    struct payload_args *args = payload_context(syscall, msg->fd, is_rx);
    if (!args)
        goto out;
    for (__u32 i = 0; i < 28; i++) {
        if (i >= msg->iovlen)
            goto out;
        struct iovec first = {};
        if (bpf_probe_read_user(&first, sizeof(first), (void *)(msg->iovec_ptr + i * sizeof(first)))) {
            capture_read_failed(msg->fd, is_rx, false);
            goto out;
        }
        if (!first.iov_len)
            continue;
        __u32 size = min_size(min_size(first.iov_len, ctx->ret), PACKET_CHUNK_SIZE);
        char buffer[PACKET_CHUNK_SIZE] = {};
        if (bpf_probe_read_user(buffer, size, first.iov_base)) {
            capture_read_failed(msg->fd, is_rx, false);
            goto out;
        }
        args->type = resolve_http_type(ctx, msg->fd, is_rx, buffer, size, ctx->ret);
        break;
    }
    if (!args->type)
        goto out;

    populate_http_metadata(&args->meta, args->sockfd, args->is_rx);
    args->remaining = ctx->ret;
    // At most 28 descriptors plus 16 extra chunks, sharing a 256-KiB byte cap.
    for (int step = 0; step < 28 + HTTP_MAX_CHUNKS; step++) {
        int result = emit_iov_step(ctx, args, msg);
        if (result < 0)
            goto out;
        if (!result)
            break;
    }
    if (flush_iov(ctx, args))
        goto out;
    if (args->remaining || args->offset < args->actual_len)
        capture_failed(msg->fd, is_rx, HTTP_LOSS_LIMIT);

out:
    bpf_map_delete_elem(&msg_packets, &id);
    return 0;
}

// -----------------------------------------------------------------------------
// READ / RECV (Inbound: is_rx = true)
// -----------------------------------------------------------------------------

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
    process_packet(ctx, "read", true);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int sys_enter_recvfrom(struct syscall_trace_enter *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }

    if (is_msg_peek(ctx->args[3])) {
        __u64 id = bpf_get_current_pid_tgid();
        bpf_map_delete_elem(&buffer_packets, &id);
        return 0;
    }
    pre_receive_syscalls(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int sys_exit_recvfrom(struct syscall_trace_exit *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }

    process_packet(ctx, "recvfrom", true);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int syscall__probe_entry_recvmsg(struct syscall_trace_enter *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }

    if (is_msg_peek(ctx->args[2])) {
        __u64 id = bpf_get_current_pid_tgid();
        bpf_map_delete_elem(&msg_packets, &id);
        return 0;
    }
    pre_process_msg(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvmsg")
int syscall__probe_ret_recvmsg(struct syscall_trace_exit *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }

    process_msg(ctx, "recvmsg", true);
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
    process_msg(ctx, "readv", true);
    return 0;
}

// -----------------------------------------------------------------------------
// WRITE / SEND (Outbound: is_rx = false)
// -----------------------------------------------------------------------------

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

    process_packet(ctx, "write", false);
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

    process_packet(ctx, "sendto", false);
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

    process_msg(ctx, "sendmsg", false);
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

    process_msg(ctx, "writev", false);
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
