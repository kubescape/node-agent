#pragma once

#include <gadget/types.h>

struct event {
    gadget_timestamp timestamp_raw;
    struct gadget_process proc;
    bool upper_layer;
    __u32 exit_code;
    __u32 exit_signal;
    __u32 exit_pid;
    __u32 exit_tid;
    __u32 exit_ppid;
};
