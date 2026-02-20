// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 The Inspektor Gadget authors */

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/filesystem.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#include "go_argument.h"

#define GOTLS_RANDOM_SIZE 32
#define MAX_DATA_SIZE_OPENSSL 1024 * 16
#define GOTLS_EVENT_TYPE_WRITE 0
#define GOTLS_EVENT_TYPE_READ 1

// // TLS record types in golang tls package
#define recordTypeApplicationData 23

struct event {
    u64 ts_ns;
    u32 pid;
    u32 tid;
    s32 data_len;
    u8 event_type;
    char comm[TASK_COMM_LEN];
    char data[MAX_DATA_SIZE_OPENSSL];
};

GADGET_TRACER_MAP(events, 4096*4096); // 4096 in-flight pages
GADGET_TRACER(raw, events, event);

static __always_inline int gotls_write(struct pt_regs *ctx, bool is_register_abi) {
    s32 record_type, len;
    const char *str;
    void *record_type_ptr;
    void *len_ptr;
    record_type_ptr = (void *)go_get_argument(ctx, is_register_abi, 2);
    bpf_probe_read_kernel(&record_type, sizeof(record_type), (void *)&record_type_ptr);
    str = (void *)go_get_argument(ctx, is_register_abi, 3);
    len_ptr = (void *)go_get_argument(ctx, is_register_abi, 4);
    bpf_probe_read_kernel(&len, sizeof(len), (void *)&len_ptr);

    if (len == 0) {
	bpf_printk("first return");
        return 0;
    }
    bpf_printk("gotls_write record_type:%d, len:%d", record_type, len);
    if (record_type != recordTypeApplicationData) {
	bpf_printk("second return");
        return 0;
    }

    struct event *event;
    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event) return 0;
    u64 id = bpf_get_current_pid_tgid();
    event->ts_ns = bpf_ktime_get_ns();
    event->pid = id >> 32;
    event->tid = (__u32)id;
    event->event_type = GOTLS_EVENT_TYPE_WRITE;
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    event->data_len =
        (len < MAX_DATA_SIZE_OPENSSL ? (len & (MAX_DATA_SIZE_OPENSSL - 1))
                                     : MAX_DATA_SIZE_OPENSSL);
    int ret = bpf_probe_read_user(&event->data, event->data_len, (void *)str);
    #pragma unroll
    for (int i = 0; i < 256; i++) {
      if (i >= event->data_len)break;

      bpf_printk("data[%d]=%c", i, (u8)event->data[i]);
    }
    /*
    if (ret < 0) {
        gadget_discard_buf(&event);
        bpf_printk("gotls_write bpf_probe_read_user_str failed, ret:%d, str:%d\n", ret, str);
	bpf_printk("last return");
        return 0;
    }
    */

    bpf_printk("Writing data to perf buffer");
    gadget_submit_buf(ctx, &events, event, sizeof(*event));
    return 0;
}

// Actually uprobe, but hacking to make user space attaching logic happy
SEC("uretprobe//usr/bin/kubelet:crypto/tls.(*Conn).Write")
int uprobe_write(struct pt_regs *ctx) {
	bpf_printk("gotls_write_register triggered");
	return gotls_write(ctx, true);
}

// crypto/tls/conn.go
// func (c *Conn) Read(b []byte) (int, error)
static __always_inline int gotls_read(struct pt_regs *ctx, bool is_register_abi) {
    s32 record_type, ret_len;
    const char *str;
    void *len_ptr, *ret_len_ptr;

    // golang
    // uretprobe的实现，为选择目标函数中，汇编指令的RET指令地址，即调用子函数的返回后的触发点，此时，此函数参数等地址存放在SP(stack
    // Point)上，故使用stack方式读取
    // str 是 Golang TLS  *Conn.Read函数第一个参数b []byte的类型，对应runtime中

    str = (void *)go_get_argument(ctx, false, 2);
    if (is_register_abi) {
        ret_len_ptr = (void *)go_get_argument(ctx, is_register_abi, 1);
    } else {
        // by stack, Read函数的返回值第一个是int类型，存放在栈里的顺序是5
        ret_len_ptr = (void *)go_get_argument(ctx, is_register_abi, 5);
    }
    bpf_probe_read_kernel(&ret_len, sizeof(ret_len), (void *)&ret_len_ptr);
    bpf_printk("gotls_read event, str:%p ret_len_ptr:%d, ret_len:%d\n", str, ret_len_ptr, ret_len);
    if (str <= 0) {
        return 0;
    }
    if (ret_len <= 0) {
        return 0;
    }

    struct event *event;
    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event) return 0;
    u64 id = bpf_get_current_pid_tgid();
    event->ts_ns = bpf_ktime_get_ns();
    event->pid = id >> 32;
    event->tid = (__u32)id;
    event->event_type = GOTLS_EVENT_TYPE_READ;
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    event->data_len = (ret_len < MAX_DATA_SIZE_OPENSSL ? (ret_len & (MAX_DATA_SIZE_OPENSSL - 1)) : MAX_DATA_SIZE_OPENSSL);
    int ret = bpf_probe_read_user(&event->data, event->data_len, (void *)str);
    #pragma unroll
    for (int i = 0; i < 256; i++) {
      if (i >= event->data_len)break;

      bpf_printk("data[%d]=%c", i, (u8)event->data[i]);
    }
    /*
    if (ret < 0) {
        gadget_discard_buf(&event);
        bpf_printk("gotls_text bpf_probe_read_user_str failed, ret:%d, str:%d\n", ret, str);
        return 0;
    }
    */
    bpf_printk("Writing data to perf buffer");
    gadget_submit_buf(ctx, &events, event, sizeof(*event));
    return 0;
}

// capture golang tls plaintext, supported golang stack-based ABI (go version
// < 1.17) func (c *Conn) Read(b []byte) (int, error)

// Actually uprobe, but hacking to make user space attaching logic happy
SEC("uretprobe//usr/bin/kubelet:crypto/tls.(*Conn).Read")
int uprobe_read(struct pt_regs *ctx) {
	bpf_printk("gotls_read_register triggered");
	return gotls_read(ctx, true);
}

char LICENSE[] SEC("license") = "GPL";
