#pragma once

#include <gadget/types.h>
#include <gadget/filesystem.h>

struct event {
    gadget_timestamp timestamp_raw;
    struct gadget_process proc;
    char exepath[GADGET_PATH_MAX];
    uint32_t cmd;
    uint32_t attr_size;
    bool upper_layer;
};
