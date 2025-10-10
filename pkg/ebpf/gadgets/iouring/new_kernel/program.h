#pragma once

#include <gadget/types.h>

struct event {
    gadget_timestamp timestamp_raw;
    struct gadget_process proc;
    __u32 opcode;
    __u32 flags;
};
