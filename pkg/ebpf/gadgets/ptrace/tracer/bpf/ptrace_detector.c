#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/filter.h>

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

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_enter_ptrace(struct syscalls_enter_ptrace_args *ctx)
{
    long request = ctx->request;
    long pid = ctx->pid;
    bpf_printk("Hello from eBPF program: request=%ld, pid=%d\n", request, pid);

    if (request == PTRACE_SETREGS || request == PTRACE_POKETEXT || request == PTRACE_POKEDATA) {
        bpf_printk("Malicious ptrace detected: request=%ld, pid=%d\n", request, pid);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
