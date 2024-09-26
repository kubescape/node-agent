#include "../../../../include/amd64/vmlinux.h"
#include "../../../../include/types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "../../../../include/mntns_filter.h"
#include "../../../../include/filesystem.h"
#include "../../../../include/macros.h"
#include "../../../../include/buffer.h"

#define TASK_COMM_LEN 16
#define MAX_STRING_SIZE    4096       

#ifndef PTRACE_SETREGS
#define PTRACE_SETREGS 13
#endif

#ifndef PTRACE_POKETEXT
#define PTRACE_POKETEXT 4
#endif

#ifndef PTRACE_POKEDATA
#define PTRACE_POKEDATA 5
#endif

struct syscalls_enter_ptrace_args {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;

    __s32 __syscall_nr;
    __u64 request;
    __u64 pid;
    __u64 addr;
    __u64 data;
};  

struct event {
    gadget_timestamp timestamp;
    gadget_mntns_id mntns_id;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u32 request;
    __u8 comm[TASK_COMM_LEN];
    __u8 exepath[MAX_STRING_SIZE];
};
