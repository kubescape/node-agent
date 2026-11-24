# Open `nsPid` CEL field

`event.nsPid` is the PID (thread group ID) of the process that made the open,
as seen in the process's own PID namespace: the number the process sees for
itself in `/proc`. `event.pid` is the same process seen from the host, so the
two differ for a containerized process:

| Process | `event.pid` | `event.nsPid` | Its own `/proc` path |
|---|---|---|---|
| PID 29 in a container | `926143` | `29` | `/proc/29/...` |
| A process on the host | `4242` | `4242` | `/proc/4242/...` |

Rules use it to tell an open of the process's **own** `/proc/<pid>/...` files
from another process's. A process reading its own `environ` learns nothing new,
while reading another process's can steal secrets (R0008). Writing another
process's `mem` is code injection, while writing its own can be a monitoring
agent (R1034):

```cel
event.nsPid > 0u && event.path.startsWith('/proc/' + string(event.nsPid) + '/')
```

## Semantics

- **Thread group, not thread.** The value is the TGID, so a Java thread that
  opens `/proc/<pid>/...` of its process matches, even though its own thread ID
  differs.
- **Captured at event time.** `trace_open` reads it in eBPF from
  `current->group_leader->thread_pid->numbers[level].nr` when the open returns.
  Nothing reads `/proc` later, so short-lived processes are covered.
- **`0` means unknown.** It is 0 when the kernel read fails, for events of
  other types, and for a `trace_open` image without the field. A rule must
  treat 0 as "not own" (the `> 0u` guard above), so missing data never hides an
  alert.
- **`/proc` of another PID namespace.** `/proc/<pid>` paths resolve in the PID
  namespace of the mounted procfs, not of the process. The own-`/proc` check above
  is exact only when the process's `/proc` belongs to its own PID namespace, which
  is the default for a container. When a container mounts the procfs of another
  namespace at `/proc`, for example the host's without `hostPID`, the numbers can
  collide: a process with `nsPid` 29 that opens `/proc/29/environ` reads host PID
  29, and the check still calls it "own". A rule that uses the check as an
  exemption then hides that alert. Such a mount already gives the container the
  host's process table. Keep that in mind when you use `nsPid` to suppress
  alerts, and do not rely on it for workloads that mount a foreign procfs at
  `/proc`. A procfs mounted elsewhere (such as `/host/proc`) never matches the
  `/proc/` prefix, so it is not exempted.
- **Type.** `uint`, like `event.pid`: compare with `0u`, not `0`.

`StructEvent` (ptrace and tests) carries it in `NsPid`.

## Alerts

The open rule adapter adds `nsPid` to the alert arguments when it is not 0.

## Version gate

An agent built before this field existed does not register `event.nsPid`, so a
rule that references it fails to compile there and is skipped. Gate such rules
with `agentVersionRequirement` set to the first release that carries this
change (kubescape/node-agent, and for private agents the first
private-node-agent release that pins it).

## Code

- `pkg/ebpf/gadgets/trace_open/program.bpf.c`: `current_ns_tgid()` fills `nspid`.
- `pkg/utils/datasource_event.go`, `pkg/utils/struct_event.go`: `GetNsPID()`.
- `pkg/utils/cel.go`: the `nsPid` entry in `CelFields`.
- `pkg/rulemanager/cel/cel_nspid_test.go`: own, other, prefix, unknown and
  missing-field cases against both `StructEvent` and a synthetic open datasource.
