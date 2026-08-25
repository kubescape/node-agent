# Syscall Poll Interval and Termination Grace Period

Container profiles could end up with 0 or partial syscalls even when the container executed
tens of distinct syscalls (kubescape/node-agent#922). This documents the root cause and the
mitigation.

## Root cause

`SyscallTracer` (pkg/containerwatcher/v2/tracers/syscall.go) doesn't read the kernel's
`advise_seccomp` eBPF map on demand. It runs the `advise_seccomp` OCI gadget with a periodic
map-fetch: every poll interval, the gadget operator drains the whole map
(`BPF_MAP_LOOKUP_AND_DELETE_BATCH`) and emits one datasource event per entry, which
`SyscallTracer.callback` decodes and routes to `ContainerProfileManager.ReportSyscall` by
container ID. Until the fix below, that interval was hardcoded to 30 seconds.

`ContainerProfileManager` (pkg/containerprofilemanager/v1) reacts to container termination
synchronously: `deleteContainer` sends `ContainerHasTerminatedError` on the container's sync
channel, and `monitorContainer` (pkg/containerprofilemanager/v1/monitoring.go) immediately does
a final forced `saveProfile` and hands the ack back. Whatever syscalls the kernel recorded since
the tracer's last poll are still sitting in the eBPF map at that moment — they have not been
fetched yet — and once the profile is saved and the container's entry is removed
(`removeContainerEntry`), that data is unreachable. A container whose lifetime is shorter than
the poll interval could complete with zero syscalls recorded; any container has up to one full
poll interval of syscalls at risk on termination.

There is no per-container on-demand flush available from the pinned `advise_seccomp` gadget: the
eBPF map iterator (`pkg/operators/ebpf/maps.go` in the `inspektor-gadget` fork) only supports a
fixed interval/count and an optional flush-on-stop that fires when the whole gadget instance
stops — not when one container among many terminates. Re-introducing a true synchronous
`Peek()` (as node-agent v1 had) would require changing that upstream gadget's fetch loop to
support an on-demand trigger, which is out of scope here.

## Mitigation

Two changes narrow the race instead, both purely on the node-agent side:

1. **`syscallPollInterval` config** (default `2s`, was hardcoded `30s`) — passed to the gadget as
   `operator.oci.ebpf.map-fetch-interval` (`SyscallTracer.pollInterval()`). Shortening the
   interval bounds how much syscall data can be sitting unfetched in the kernel map at any given
   moment, from up to 30s down to the configured value.

2. **Termination grace period** — `ContainerProfileManager.terminationGracePeriod()`
   (pkg/containerprofilemanager/v1/helpers.go) sleeps for `min(syscallPollInterval, 5s)`
   immediately before the final forced `saveProfile` call on both termination paths
   (`ContainerHasTerminatedError` and `ContainerReachedMaxTime` in monitoring.go). This gives the
   next poll cycle — which is already running independently of any single container's lifecycle
   — a chance to fetch and report the last syscalls before they become unreachable. The 5s cap
   protects against a misconfigured (large) `syscallPollInterval` stalling every container
   termination by that same amount; `MaxWaitForAck` (30s) has ample headroom above the cap.

Together these shrink the loss window from "up to 30s, every termination" to "up to
`syscallPollInterval` (default 2s), and only when a poll genuinely didn't fire in that window" —
without touching the gadget's fetch mechanism.

## Known limitations

This is a bounded-race mitigation, not a guarantee. A container that terminates and whose final
poll cycle is delayed (e.g. by scheduler contention) beyond the grace period can still lose its
most recent syscalls. Achieving zero-loss capture would require an on-demand, per-container flush
in the underlying gadget (`matthyx/inspektor-gadget`), tracked as a separate follow-up.

Shortening the poll interval means more frequent map fetches. Each fetch drains the entire
`advise_seccomp` map for every actively-traced container's mount namespace in one batch (not just
one), so the added overhead is one small periodic drain rather than N per-container calls; syscall
events reaching `ContainerProfileManager` are further deduplicated per (mount ns, pid, syscall)
within a 5s window (`dedupTTLSyscall`, pkg/containerwatcher/v2/event_handler_factory.go), which
absorbs most of the added repeat-event volume from polling more often.
