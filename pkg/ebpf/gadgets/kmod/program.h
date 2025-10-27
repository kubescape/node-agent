#pragma once

#include <gadget/types.h>
#include <gadget/filesystem.h>

struct event {
    gadget_timestamp timestamp_raw;
    struct gadget_process proc;
    char syscall[16];
    char module[GADGET_PATH_MAX];
    char exepath[GADGET_PATH_MAX];
    bool upper_layer;
};
