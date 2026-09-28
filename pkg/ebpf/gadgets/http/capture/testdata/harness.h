// Native helper substitutes. The test compiles the production header and all
// production probe bodies unchanged apart from their kernel-only includes.
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
typedef uint8_t __u8, u8;
typedef uint16_t __u16, u16;
typedef uint32_t __u32, u32;
typedef uint64_t __u64;
typedef uint64_t gadget_timestamp;
#define SEC(s)
#define __noinline __attribute__((noinline))
#define __uint(name, value) int *name
#define __type(name, value) value *name
#define BPF_MAP_TYPE_LRU_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERCPU_ARRAY 3
#define BPF_ANY 0
#define GADGET_TRACER_MAP(name, size) int name
#define GADGET_TRACER(...)
#define BPF_CORE_READ(ptr, field) ((ptr)->field)
#define bpf_ntohs(x) (x)
struct gadget_process { int pid; };
struct gadget_l4endpoint_t { int port, version; struct { int v4; } addr_raw; };
struct inode { __u64 i_ino; };
struct sock { struct { int skc_num, skc_rcv_saddr, skc_dport, skc_daddr; } __sk_common; };
struct socket { struct sock *sk; };
struct file { struct inode *f_inode; struct socket *private_data; };
struct fdtable { struct file **fd; };
struct files_struct { struct fdtable *fdt; };
struct task_struct { struct files_struct *files; };
static struct inode inode = {.i_ino=123};
static struct file file = {.f_inode=&inode};
static struct file *fds[] = {&file};
static struct fdtable fdt = {.fd=fds};
static struct files_struct files = {.fdt=&fdt};
static struct task_struct task = {.files=&files};
static void *bpf_get_current_task(void) { return &task; }
struct syscall_trace_enter { __u64 args[6]; };
struct syscall_trace_exit { long ret; };
struct user_msghdr { struct iovec *msg_iov; __u64 msg_iovlen; };
static __u64 bpf_get_current_pid_tgid(void) { return 1; }
static __u64 bpf_ktime_get_boot_ns(void) { return 1; }
static int gadget_should_discard_data_current(void) { return 0; }
#define gadget_process_populate(proc) ((proc)->pid=1)
static int bpf_probe_read(void *dst, size_t n, const void *src) { memcpy(dst, src, n); return 0; }
static void *reserved;
static int reserve_calls, fail_reserve, copy_calls, fail_copy;
static int bpf_probe_read_user(void *dst, size_t n, const void *src) {
    if (reserved && (uintptr_t)dst >= (uintptr_t)reserved && (uintptr_t)dst < (uintptr_t)reserved+20000 && ++copy_calls == fail_copy) return -1;
    memcpy(dst, src, n); return 0;
}
static int bpf_probe_read_str(void *dst, size_t n, const void *src) { snprintf(dst, n, "%s", (const char *)src); return 0; }
static void *gadget_reserve_buf(void *map, size_t n) { (void)map; if (++reserve_calls == fail_reserve) return NULL; reserved=calloc(1,n); return reserved; }
static void gadget_discard_buf(void *e) { free(e); reserved=NULL; }
static void gadget_submit_buf(void *, void *, void *, size_t);
static struct entry { void *map; size_t keylen; unsigned char key[32]; union { __u64 align; unsigned char bytes[256]; } value; } entries[32];
static __u64 losses[3];
static void *lookup(void *map, const void *key, size_t keylen);
static int update(void *map, const void *key, size_t keylen, const void *v, size_t n) {
    for (int i=0;i<32;i++) if (entries[i].map==map && !memcmp(entries[i].key,key,keylen)) { memcpy(entries[i].value.bytes,v,n); return 0; }
    for (int i=0;i<32;i++) if (!entries[i].map) { entries[i].map=map; entries[i].keylen=keylen; memcpy(entries[i].key,key,keylen); memcpy(entries[i].value.bytes,v,n); return 0; }
    abort();
}
static int delete(void *map, const void *key, size_t n) { for(int i=0;i<32;i++) if(entries[i].map==map && !memcmp(entries[i].key,key,n)) entries[i].map=NULL; return 0; }
#define bpf_map_lookup_elem(m,k) lookup(m,k,sizeof(*(m)->key))
#define bpf_map_update_elem(m,k,v,f) update(m,k,sizeof(*(m)->key),v,sizeof(*(m)->value))
#define bpf_map_delete_elem(m,k) delete(m,k,sizeof(*(m)->key))
