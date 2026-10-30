# Process tree — re-reading an exec's parent after `runc exec`

A `kubectl exec` (or any `runc exec`) starts a process whose parent depends on
timing. When its exec event is captured, the parent is either:

- the **containerd-shim**, if `runc exec` has already exited and the kernel has
  reparented the process; or
- the **runc** process, if runc is still alive.

runc is a host process. In Kubernetes mode the tree holds only a parentless
placeholder for it, so the branch from the exec'd process never reaches the
shim. `GetPidBranch` then fails and the alert falls back to a depth-1 tree whose
parent is `runc` and whose start time is zero. Before this fix only a later exec
on the same pid repaired it, through `UpdatePPID`. CI saw this on roughly 30% of
process-tree roots, which made `Test_24_ProcessTreeDepthTest` flaky.

## What the creator does

`handleExecEvent` calls `rereadUnknownParent` after the normal `UpdatePPID`. It
re-reads the process's **current** parent from `/proc/<pid>/stat` field 4. By
the time the event is handled, runc has usually exited and the parent is the
shim.

| Step | Rule |
|---|---|
| Gate | Kubernetes mode only, a non-host container id, a non-zero parent, an acyclic chain that reaches neither pid 1 nor the container's shim. Every other exec skips the read. |
| Target | The topmost node below the unknown ancestor. This is usually the exec'd process. It is the process's parent when a child execs before the parent's chain was repaired. |
| Pid reuse (target) | Skip when the target has a pending exit. With a recorded `pidStartTimeNs`, skip unless the `/proc` start time (field 22) matches it. When the target is the exec'd process itself, its `/proc` start time must also not be later than the event's exec timestamp mapped back to the boot clock. This applies even with a recorded start time, because an earlier delayed exec may have recorded the replacement's time. A later start time means the exec was handled after its pid was recycled. If the timestamp is unknown, or the target is an ancestor with no recorded start time, skip. |
| Pid reuse (parent) | The new parent must already be a tree node with no pending exit. Its `/proc` start time is read too. It must match the node's recorded start time when there is one, and must not be later than the target's. Host shims have no recorded start time in Kubernetes mode, because host procfs events never reach the side map. |
| Adoption | Adoption goes through `UpdatePPID`, so the container-subtree rules still apply. The repaired node's `Pcomm` becomes the adopted parent's `Comm`. An exec event's `Pcomm` is applied only when the event's parent is the parent the node keeps, so a later exec that still reports runc does not relabel a repaired node. |
| No change | The pid is gone, the stat fails to parse, the parent is unchanged, or the new parent is unknown. The tree keeps today's behaviour. |

## Cost and locking

Each read is one `/proc/<pid>/stat` open-read-parse, about 7.5 µs. An adoption
takes two reads: the target and the new parent. It runs under
the tree's write lock, the same trade-off `ensureStartTime` makes on the exec
path. It is acceptable because the gate keeps it off the common path: an exec
whose parent chain is already known never reads `/proc`.

The reader is the `readParent` field on the creator (`parent_reader.go`). Tests
inject a stub in its place. If `/proc` cannot be opened, the reader retries on
the next call instead of staying disabled.

The exec timestamp is inspektor-gadget's `bpf_ktime_get_boot_ns` value plus a
fixed wall-clock offset. The creator samples the same offset once at
construction (`bootToWallNs`) and subtracts it.

## Limits

If runc is still alive when the event is handled, the read returns runc and
nothing changes. The next exec in that subtree, or the next `/proc` scan, can
still repair the chain.
