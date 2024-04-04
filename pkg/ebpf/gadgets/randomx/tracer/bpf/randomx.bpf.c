#include "../../../../include/amd64/vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "randomx.h"
#include "../../../../include/mntns_filter.h"
#include "../../../../include/macros.h"
#include "../../../../include/buffer.h"

// Events map.
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

// we need this to make sure the compiler doesn't remove our struct.
const struct event *unusedevent __attribute__((unused));

const volatile uid_t targ_uid = INVALID_UID;

static __always_inline bool valid_uid(uid_t uid)
{
	return uid != INVALID_UID;
}

static __always_inline bool has_upper_layer()
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct inode *inode = BPF_CORE_READ(task, mm, exe_file, f_inode);
	if (!inode) {
		return false;
	}
	unsigned long sb_magic = BPF_CORE_READ(inode, i_sb, s_magic);

	if (sb_magic != OVERLAYFS_SUPER_MAGIC) {
		return false;
	}

	struct dentry *upperdentry;

	// struct ovl_inode defined in fs/overlayfs/ovl_entry.h
	// Unfortunately, not exported to vmlinux.h
	// and not available in /sys/kernel/btf/vmlinux
	// See https://github.com/cilium/ebpf/pull/1300
	// We only rely on vfs_inode and __upperdentry relative positions
	bpf_probe_read_kernel(&upperdentry, sizeof(upperdentry),
			      ((void *)inode) +
				      bpf_core_type_size(struct inode));
	return upperdentry != NULL;
}

SEC("tracepoint/x86_fpu/x86_fpu_regs_deactivated")
int tracepoint__x86_fpu_regs_deactivated(struct trace_event_raw_x86_fpu *ctx) {
    struct event event = {};

    struct task_struct *current_task = (struct task_struct*)bpf_get_current_task();
    if (!current_task) {
        return 0;
    }

    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = (u32)uid_gid;

    if (valid_uid(targ_uid) && targ_uid != uid) {
        return 0;
    }

    u64 mntns_id = BPF_CORE_READ(current_task, nsproxy, mnt_ns, ns.inum);

    if (gadget_should_discard_mntns_id(mntns_id)) {
        return 0;
    }

    void *fpu = BPF_CORE_READ(ctx, fpu);
    if (fpu == NULL) {
        return 0;
    }

    u32 mxcsr;
    // Since kernel 5.15, the fpu struct has been changed and CO-RE isn't able to read it.
    // We need to use the bpf_probe_read_kernel helper to read the mxcsr value.
    // The old_fpu struct is used for kernels <= 5.15.
    #if LINUX_KERNEL_VERSION <= KERNEL_VERSION(5, 15, 0)
        bpf_probe_read_kernel(&mxcsr, sizeof(mxcsr), &((struct old_fpu*)fpu)->state.xsave.i387.mxcsr);
    #else
        mxcsr = BPF_CORE_READ((struct fpu*)fpu, fpstate, regs.xsave.i387.mxcsr);
    #endif
    
    int fpcr = (mxcsr & 0x6000) >> 13;
    if (fpcr != 0) {
        __u32 ppid = BPF_CORE_READ(current_task, real_parent, pid);
        /* event data */
        event.timestamp = bpf_ktime_get_boot_ns();
        event.mntns_id = mntns_id;
        event.pid = bpf_get_current_pid_tgid() >> 32;
        event.ppid = ppid;
        event.uid = uid;
        event.gid = (u32)(uid_gid >> 32);
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        event.upper_layer = has_upper_layer();

        /* emit event */
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
