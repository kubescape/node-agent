# gVisor initial-task stop mapping, 11 November 2026

This follows the [terminal-signal investigation](../gvisor-terminal-20261106/README.md)
from #1081. That run found a candidate correlation between a container's initial
task and its CRI exit status, but left the identity mapping, PID reuse,
deduplication and loss cases open. This experiment tests one specific mapping
against independent CRI records across a wider case matrix. It still does not
add a production stop collector, and the emitted production-stop count is zero.

## Candidate rule

For each `container/start` claim, take the key
`(container_id, thread_group_id, thread_group_start_time)` from its context.
A terminal candidate is a `sentry/task_exit` or `sentry/exit_notify_parent`
record whose context has the same key and whose `thread_id` equals the thread
group ID (the group leader). Both point types for one key count as one
termination. The wait status is mapped to a CRI-style code: the exit code when
the process exited, otherwise 128 plus the signal.

The trial selects `task_start_time` and `thread_group_start_time` in addition to
the fields #1081 used. Both are available on all three points in the pinned
runsc build.

## Result

Three full runs were kept (`run-b`, `run-c`, `run-d`). Each has 18 workload
containers across 12 cases and 121 retained records. The results were the same
in all three runs except for timing.

| Case | CRI exit | Rule result (each run) |
|---|---|---|
| Normal exit with a child | 7 | One termination, status 1792 → 7. The child exit is excluded. |
| Short-lived (`exit 5`) | 5 | One termination, 1280 → 5. |
| Graceful stop, TERM handled | 3 | One termination, 768 → 3. The orphaned `sleep` exits *after* the init task and is excluded. |
| Graceful stop, default TERM | 143 | One termination, status 15 → 143. |
| Grace timeout, TERM ignored | 137 | One termination, status 9 → 137. The child exits afterwards and is excluded. |
| SIGKILL | 137 | One termination, 9 → 137. |
| `kubectl exec` session exits 4 | 137 (later kill) | The exec task's exit (1024) is excluded. CRI showed RUNNING one second after it. |
| Sentry process killed | 128 | **No terminal record.** Only the connection closes. |
| Two containers in one Pod | 11, 12 | One termination each, under different thread groups (2 and 3). |
| Four concurrent sandboxes | 21–24 | One termination each. Every one uses thread group 2. |
| Restart in the same sandbox | 13, 13 | One termination per instance. The second instance got thread group 3, not 2. |
| Receiver restart | 17, 18 | **The sandbox connected before the restart lost its stream; its exit was never observed.** The sandbox created after the restart was observed normally. |

Across the three runs, 48 of 48 observed terminations matched the CRI exit code.
The 6 missing terminations are exactly the Sentry-kill and pre-restart cases.
No non-init task, exec session or child exit matched the rule. Receiver
counters show zero decode/transport errors, zero queue drops and zero rejected
clients. That is not proof of complete delivery.

Default TERM handling differs from what an ordinary Linux container would show.
The init shell with no TERM handler was killed by SIGTERM (143), and did not
ignore it until the SIGKILL escalation. An exploratory first run expected 137
here and stopped at that case. The run was not retained, and the case was split
into the two TERM variants above.

## What this shows and what it does not

**Identity.** Thread group IDs repeat across sandboxes: every sandbox's first
workload container was thread group 2. So the thread group alone, or the PID
alone, cannot identify a container. Within a sandbox, a restarted container got
a new thread group. The start time in the key makes reuse inside one sandbox
detectable in principle, but these runs did not force PID wraparound inside a
sandbox.

**Sandbox teardown.** Each Pod's pause container also produces a start claim
and a matching init exit, keyed by the sandbox ID (14 per run). The rule cannot
tell these apart from container stops by itself. A production path must resolve
the claimed ID against runtime inventory and keep sandbox teardown separate.

**Deduplication.** Every observed termination produced exactly one `task_exit`
and one `exit_notify_parent` with the same key and status. The parent
notification came 0.16–6.4 ms later.

**Ordering against CRI.** CRI's `finishedAt` was 2.8–17.8 ms after the Sentry's
exit time, and a few CRI RUNNING samples fell after the Sentry record (1, 1 and
6 per run). A stop observation can therefore arrive before CRI reports the
container exited. Reconciliation has to tolerate that and must not treat it as
a conflict.

**Loss.** This is the main limit. When the Sentry dies there is no terminal
record at all, and CRI reports 128. When the receiver restarts, the runtime
does not reconnect existing sandboxes, so every later exit from them is lost.
Both cases are expected, and they are not rare edge cases. The trace source
cannot be the only authority for container termination.

## Is the stop contract ready?

The mapping itself held in every case where the stream was intact. The key,
the deduplication and the exit-code mapping were consistent across all three
runs. A defensible contract would be:

1. Observe a stop only for an inventory-verified workload container (not a
   sandbox ID) with exactly one resolved start claim on a live connection.
2. Emit at most one stop per key, from whichever terminal point arrives first.
   Treat the second point as confirmation only.
3. Never derive a stop from a connection close, a non-leader task or another
   thread group.
4. On disconnect or receiver restart, mark that connection's containers as
   unobserved. Leave their termination to CRI reconciliation, labelled as a
   runtime source and not as a gVisor observation.

Whether that is worth building, compared with relying on CRI alone, is a
maintainer decision. No implementation is proposed here.

## Coverage and environment

All runs used one self-managed ARM64 Ubuntu VM (kernel 6.8.0-147-generic,
K3s v1.37.1+k3s1) and runsc release-20261019.0 with systrap. The binary hash and
the full metadata hash are in [environment.json](evidence/environment.json).
The metadata hash matches the #1081 run. Not covered: PID wraparound inside a
sandbox, OOM kills, node or runsc restarts, more than four concurrent
sandboxes, x86_64, managed GKE, and any overhead measurement.

## Privacy and bounds

The receiver accepts only message types 1, 4 and 5. It retains numeric context
fields, claimed 64-character hexadecimal IDs, wait status and a per-connection
counter. It discards argv, cwd, env, credentials and process names, and clears
raw buffers after parsing. Records, clients and packet sizes are capped. A
canary in every container's argv and working directory, including the exec
session's argv, was checked to be absent from the retained records. Like the
#1081 receiver, this is a disposable research tool. Do not enable it as a
node-agent source or expose its socket to Pods.

## Reproduce on a disposable node

1. Save the existing runsc runtime configuration privately. Point it at
   [pod-init.json](pod-init.json) with `pod-init-config`, so new sandboxes use an
   experiment-owned `Default` session. Do not use `--force` or replace another
   monitor's session.
2. Make sure `/run/kubescape` is a root-owned 0700 directory. The trial expects a
   RuntimeClass `gvisor` mapped to handler `runsc`. Run as root on the node:

   ```sh
   python3 trial.py --namespace gvisor-stopmap-20261111-x --output NEW_DIRECTORY
   python3 analyze.py NEW_DIRECTORY
   ```

   The Sentry-failure case sends SIGKILL only to the `runsc-sandbox` process
   whose arguments name the trial Pod's sandbox ID. It refuses to act if it
   finds none or more than one.
3. Delete the trial namespace, restore the saved runtime configuration and
   remove `/run/kubescape/gvisor-stopmap`.

Unit tests (decoder, status mapping, retained evidence and negative cases):

```sh
python3 -m unittest discover -s docs/experiments/gvisor-stop-mapping-20261111 -p 'test_*.py'
```

Artifact hashes are in [evidence-sha256.json](evidence-sha256.json).
