#pragma once

#include <gadget/filesystem.h>

struct event {
    gadget_timestamp timestamp_raw;
    struct gadget_process process;
    char exepath[GADGET_PATH_MAX];
    int parent_pid;
    int child_pid;
    int child_tid;
};


