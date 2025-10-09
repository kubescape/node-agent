#pragma once

#include <gadget/types.h>
#include <gadget/filesystem.h>

struct event {
    gadget_timestamp timestamp_raw;
    struct gadget_process process;
    __u32 request;
    char exepath[GADGET_PATH_MAX];
};


