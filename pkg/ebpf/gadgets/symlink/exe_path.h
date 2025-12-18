// Helper to read the current task's executable path into a buffer.
#pragma once

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <gadget/filesystem.h>

static __always_inline long read_exe_path(char *buf, __u64 buf_len)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return -1;
    }

    struct file *exe_file = BPF_CORE_READ(task, mm, exe_file);
    if (!exe_file) {
        return -1;
    }

    char *exepath = get_path_str(&exe_file->f_path);
    if (!exepath) {
        return -1;
    }
    return bpf_probe_read_kernel_str(buf, buf_len, exepath);
}


