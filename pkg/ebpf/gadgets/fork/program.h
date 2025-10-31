#pragma once

#include <gadget/filesystem.h>

struct event {
    gadget_timestamp timestamp_raw;
    struct gadget_process proc;
    char exepath[GADGET_PATH_MAX];
    uint32_t parent_pid;
    uint32_t child_pid;
    uint32_t child_tid;
};
