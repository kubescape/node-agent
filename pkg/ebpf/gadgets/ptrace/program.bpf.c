// Kernel types definitions
#include <vmlinux.h>

// eBPF helpers signatures
// Check https://man7.org/linux/man-pages/man7/bpf-helpers.7.html to learn
// more about different available helpers
#include <bpf/bpf_helpers.h>

// Inspektor Gadget buffer
#include <gadget/buffer.h>

// Helpers to handle common data
#include <gadget/common.h>

// Inspektor Gadget macros
#include <gadget/macros.h>

// Inspektor Gadget filtering
#include <gadget/filter.h>

// Inspektor Gadget types
#include <gadget/types.h>

// Inspektor Gadget mntns
#include <gadget/mntns.h>

#include "program.h"
#include "exe_path.h"

// events is the name of the buffer map and 1024 * 256 (256KB) is its size.
GADGET_TRACER_MAP(events, 1024 * 256);

// Define a tracer
GADGET_TRACER(ptrace, events, event);

#ifndef PTRACE_SETREGS
#define PTRACE_SETREGS 13
#endif
#ifndef PTRACE_POKETEXT
#define PTRACE_POKETEXT 4
#endif
#ifndef PTRACE_POKEDATA
#define PTRACE_POKEDATA 5
#endif

static __always_inline int should_capture(long request)
{
    return request == PTRACE_SETREGS || request == PTRACE_POKETEXT || request == PTRACE_POKEDATA;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_enter_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    if (gadget_should_discard_data_current()) {
        return 0;
    }

    long request = (long)ctx->args[0];
    if (!should_capture(request)) {
        return 0;
    }

    struct event *event;
    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event) {
        return 0;
    }

    // Populate the process data into the event.
    gadget_process_populate(&event->proc);
    // Ptrace info
    event->request = request;
    read_exe_path(event->exepath, sizeof(event->exepath));

    gadget_submit_buf(ctx, &events, event, sizeof(*event));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
