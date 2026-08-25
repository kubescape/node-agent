# Syscall Termination Flush

Container profiles could end up with 0 or partial syscalls even when the container executed
tens of distinct syscalls (kubescape/node-agent#922). This documents the root cause and the fix.

## Root cause

`SyscallTracer` (pkg/containerwatcher/v2/tracers/syscall.go) doesn't read the kernel's
`advise_seccomp` eBPF map on demand. It runs the `advise_seccomp` OCI gadget with a periodic
map-fetch (`syscallPollInterval`, default `30s`): on each tick, the gadget operator drains the
whole map (`BPF_MAP_LOOKUP_AND_DELETE_BATCH`) and emits one datasource event per entry, which
`SyscallTracer.callback` decodes and routes to `ContainerProfileManager.ReportSyscall` by
container ID.

`ContainerProfileManager` (pkg/containerprofilemanager/v1) reacts to container termination
synchronously: `deleteContainer` sends `ContainerHasTerminatedError` on the container's sync
channel, and `monitorContainer` (pkg/containerprofilemanager/v1/monitoring.go) immediately does
a final forced `saveProfile` and hands the ack back. Whatever syscalls the kernel recorded since
the tracer's last poll are still sitting in the eBPF map at that moment — not yet fetched — and
once the profile is saved and the container's entry is removed (`removeContainerEntry`), that
data is unreachable. A container whose lifetime is shorter than the poll interval could complete
with zero syscalls recorded; any container has up to one full poll interval of syscalls at risk
on termination.

## Fix: an on-demand flush trigger

Rather than shrinking the poll interval (which only narrows the race, and trades it for more
frequent map fetches at 30s cadence for every container node-wide), this recovers the
at-risk data directly: `ContainerProfileManager` requests an immediate, out-of-band fetch of the
eBPF map right before a container's final forced save, instead of waiting for the tracer's next
scheduled tick.

This required a small addition to the vendored `inspektor-gadget` fork
(`github.com/matthyx/inspektor-gadget`, matthyx/inspektor-gadget#12), since the OCI gadget's
map-iterator mechanism (`pkg/operators/ebpf/maps.go`) previously only supported a fixed
interval/count schedule, plus an optional flush-on-*stop* that fires when the whole gadget
instance is torn down — not when node-agent stops tracking one container among many that a
single shared, long-running gadget instance observes. `ebpfoperator.TriggerManualMapFetch(names
...string)` adds a package-level, fire-and-forget way to request an immediate fetch from any
currently running map iterator (optionally filtered by datasource name), independent of its
normal schedule.

### The pieces

1. **`SyscallTracer.Peek()`** (pkg/containerwatcher/v2/tracers/syscall.go) calls
   `ebpfoperator.TriggerManualMapFetch("syscalls")`, targeting only the seccomp tracer's map
   iterator.
2. **`ContainerProfileManager.SetSyscallFlusher`**
   (pkg/containerprofilemanager/containerprofile_manager_interface.go) lets a caller register a
   flush callback; `TracerFactory.CreateAllTracers` (pkg/containerwatcher/v2/tracers/tracer_factory.go)
   wires it to `syscallTracer.Peek`, but only when the syscall tracer is actually enabled — an
   unwired flusher would otherwise cost every container termination a wait for nothing.
3. **`flushAndSettle`** (pkg/containerprofilemanager/v1/helpers.go) is called on both
   termination paths (`ContainerHasTerminatedError` and `ContainerReachedMaxTime` in
   monitoring.go) right before the final forced `saveProfile`. It invokes the registered flusher
   (no-op if none is registered) and then waits `postSyscallFlushSettleDelay` (`500ms`) — not
   for the fetch itself, which is comparatively fast, but for the resulting events to travel
   through the ordered event queue and worker pool into this container's collected data before
   it's snapshotted and cleared.

`syscallPollInterval` still exists and still defaults to `30s`: it only governs how fresh the
*live*, still-running profile is between periodic storage updates (`updateDataPeriod`), which is
an orthogonal concern from termination-time capture now handled by the flush trigger.

## Known limitations

`TriggerManualMapFetch` is fire-and-forget — it doesn't block until the fetch completes, and
`flushAndSettle`'s fixed settle delay is a bounded wait for the event pipeline, not a guarantee
tied to the fetch itself. Under severe scheduler contention or a saturated event queue, the
flushed events could in principle still arrive after the delay elapses, in which case termination
falls back to whatever the tracer already had before the flush — the same race as before, just
far less likely to be hit since the flush is triggered immediately rather than waiting for a
30s tick. Achieving an actual guarantee would require synchronously waiting on the specific
resulting events to be processed for this container, which the event pipeline (queue +
worker pool) doesn't currently expose a way to do.
