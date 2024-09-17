#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/filter.h>

struct syscalls_enter_ptrace_args {
    __u64 __unused_syscall_nr;
    long request;
    long pid;
    unsigned long addr;
    unsigned long data;
};

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_enter_ptrace(struct syscalls_enter_ptrace_args *ctx)
{
    long request = ctx->request;
    long pid = ctx->pid;

    if (request == PTRACE_SETREGS || request == PTRACE_POKETEXT || request == PTRACE_POKEDATA) {
        bpf_printk("Malicious ptrace detected: request=%ld, pid=%d\n", request, pid);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
