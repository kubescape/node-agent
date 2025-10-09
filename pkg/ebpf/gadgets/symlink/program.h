#pragma once

#include <gadget/filesystem.h>

struct event {
    gadget_timestamp timestamp_raw;
    struct gadget_process process;
	bool upper_layer;
    char exepath[GADGET_PATH_MAX];
    char oldpath[GADGET_PATH_MAX];
    char newpath[GADGET_PATH_MAX];
};
