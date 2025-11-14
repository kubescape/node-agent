#pragma once

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// Defined in include/uapi/linux/magic.h
#define OVERLAYFS_SUPER_MAGIC 0x794c7630

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
    // We only rely on vfs_inode and __upperdentry relative positions
    bpf_probe_read_kernel(&upperdentry, sizeof(upperdentry),
                  ((void *)inode) +
                      bpf_core_type_size(struct inode));
    return upperdentry != NULL;
}


