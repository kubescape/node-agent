# gVisor terminal-signal investigation, 6 November 2026

This is the conditional stop-signal experiment from
[design #23](https://github.com/kubescape/designs-and-proposals/pull/23), following
[node-agent #1072](https://github.com/kubescape/node-agent/pull/1072). It adds a
bounded disposable research receiver and retained Linux/CRI comparisons. It does
not add a production stop collector or alter node-agent's observation contract.

## Result

The pinned runsc metadata has 980 points (its `POINTS (980)` header). The
`point_count` of 982 in [metadata.json](evidence/metadata.json) counts every
`Name:` entry in that output, which also includes the two `SINKS (2)` entries;
the retained hash covers the same output. Its only `container/` point is
`container/start`. The candidate exit points are `sentry/task_exit` and
`sentry/exit_notify_parent`, which describe tasks/thread groups. There is no
metadata point named `container/stop` in this build.

| Case | Independent CRI result | Retained trace result |
|---|---|---|
| Normal application exit | Exit code 7 | Two task-exit records for the application ID: a child and the initial thread group. The initial task's wait status is 1792 (7 shifted by 8). |
| Explicit SIGKILL | Exit code 137 | One initial-task exit with raw wait status 9. |
| Receiver disconnect | Container still RUNNING one second after deliberately closing its trace connection | No subsequent application task-exit record. The fixture later kills the workload only for cleanup, yielding CRI exit code 137. |

The normal-exit fixture keeps its parent alive after a child exits. A separate
CRI query observed RUNNING between that child event and the initial task's
exit. Thus even a task event with a matching container ID is insufficient to
mean the container stopped. The disconnect control independently shows that
transport loss is nonterminal. Socket closure remains source health.

In this run, the application start claim and CRI container ID agreed, and its
initial thread group was 2. The normal and forced-exit statuses correlate with
that specific initial task. The `exit_notify_parent` point also occurs; it must
not become a second container-stop observation for the same termination.
Do not hard-code thread group 2: each sandbox has its own PID space and mapping.

There were 17 sanitized records across all three cases, including sandbox
start claims and connection health. The research receiver counted zero decode/
transport errors and zero local queue drops. These counts do not prove complete
event delivery or explain the earlier missing-start result. An initial three-case
run was followed by the retained run with a longer child/parent gap and explicit
CRI-running samples; only the latter backs the table.

See [summary](evidence/summary.json), [runtime ledger](evidence/runtime-ledger.json),
[events](evidence/events.json), [metadata inventory](evidence/metadata.json),
[receiver accounting](evidence/receiver.json) and [environment](evidence/environment.json).
Artifact hashes are in [evidence-sha256.json](evidence-sha256.json).

## Source and identity boundaries

The VM used runsc release-20261019.0, systrap, on ARM64 Ubuntu with kernel
6.8.0-147-generic and K3s v1.37.1+k3s1. The runtime binary hash is recorded.
The same build's `runsc trace metadata` supplied point/context names. Wire
message types and fields were checked against the corresponding release's
[common.proto](https://github.com/google/gvisor/blob/release-20261019.0/pkg/sentry/seccheck/points/common.proto)
and [sentry.proto](https://github.com/google/gvisor/blob/release-20261019.0/pkg/sentry/seccheck/points/sentry.proto):
message types 4/5 carry a context and a wait-style status. Omitted scalar status
has protobuf's zero default. The decoder does not interpret syscall exit points
as container lifecycle events.

This receiver accepts only the three selected message types and retains fixed
numeric fields and 64-character hexadecimal claimed IDs. It ignores argv, cwd,
env, credentials and process names; raw buffers are cleared after parsing.
The deliberate fixture marker appears only in fixture source, not the evidence.
Six focused tests cover sensitive-field discard, malformed/truncated lengths,
varint bounds, unknown message types, retained field allowlisting and case
matrix/control requirements. This is not a general hostile-input audit.

Unlike the production start receiver, this disposable receiver does not resolve
identity before retaining the minimal claims. The offline analysis compares
claims with independently obtained CRI/Pod IDs. It does not authenticate Sentry,
attach workload findings or retain per-actor/session identity. Do not enable it
as a node-agent source or give its socket to application Pods.

## Why a production stop event is still conditional

The experiment identifies a candidate init-task correlation, not a complete
container-stop implementation. A production contract still needs:

- An inventory-verified start-to-init-task mapping with thread start time/PID
  reuse handling, rather than treating any task exit as terminal.
- Deduplication across task-exit and parent-notification points.
- Runtime reconciliation after exit and across receiver restarts, missing starts,
  missing terminal records and short-lived containers. The current start join
  requires CREATED/RUNNING state; it cannot simply be reused after termination.
- Independent multi-container, concurrent-sandbox, graceful-stop and Sentry-crash
  trials, plus privacy, bounded resource use and loss validation for the chosen
  contract. One normal, one SIGKILL and one disconnection case do not cover these.

The emitted production-stop count remains zero. No existing `RuntimeObservation`
is relabeled, and the ordinary eBPF/profile paths are unchanged.

## Reproduce on a disposable node

1. Save the existing runsc runtime configuration privately. Use an owned test
   runtime/Default session; do not use `--force` or overwrite another monitor.
   Run `runsc trace metadata` on the pinned binary and retain the selected names,
   full metadata hash and runtime version/hash.
2. Configure `--pod-init-config` before creating the test sandboxes. Select only
   `container/start`, `sentry/task_exit` and `sentry/exit_notify_parent`, each with
   `context_fields: ["time", "thread_id", "group_id", "container_id"]` and no
   optional fields. Set the remote endpoint to
   `/run/kubescape/gvisor-terminal/events.sock`. The parent directory must be
   owned by the receiver UID and private; the script creates the final directory
   if needed and refuses an existing socket.
3. The fixture expects a K3s RuntimeClass `gvisor` mapped to handler `runsc`.
   Run as root on the node:

   ```sh
   python3 trial.py --namespace gvisor-terminal-20261106-b --output NEW_DIRECTORY
   ```

   The receiver is listening before Pods are created. The image is digest-pinned.
   Queries capture no raw API errors. Each case verifies the exact CRI container
   ID and exit state. For the disconnection control it first checks RUNNING,
   then explicitly kills only that experiment's task for cleanup.
4. Run `python3 analyze.py NEW_DIRECTORY` before exporting. Review the allowlisted
   fields, identities, timestamps and counters. The checked-in unit command is:

   ```sh
   python3 -m unittest discover -s docs/experiments/gvisor-terminal-20261106 -p 'test_*.py'
   ```

5. Delete only the trial namespaces, restore the saved runtime configuration,
   stop any experiment-owned listener, and return the disposable VM to its
   original state. Never export kubeconfig, tokens, raw Pod/OCI specs or debug logs.

The checked-in evidence is one final run on one self-managed ARM64 environment.
No production Go change, full repository suite, network-egress experiment,
managed GKE access or universal terminal-event coverage is claimed.
