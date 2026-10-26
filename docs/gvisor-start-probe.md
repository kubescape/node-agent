# gVisor container start experiment

This is the first code experiment from
[the accepted runtime visibility proposal](https://github.com/kubescape/designs-and-proposals/pull/23).
It is a Linux-only, opt-in receiver for gVisor's SecCheck `container/start`
point. It does not change node-agent's normal startup, turn on tracing, or emit
existing eBPF event types.

The receiver speaks the remote sink's Unix `SOCK_SEQPACKET` protocol. It reads
the version-1 handshake and the point header, accepts only message type 1
(`MESSAGE_CONTAINER_START`), and compares the reported container ID with an
ID obtained independently from the local runtime. Other points and unresolved
IDs do not produce start events. The retained event contains the source,
container ID, observation time, and sender-reported cumulative drop count.

**Privacy boundary:** gVisor's start message includes arguments and a working
directory even when the trace session selects no optional fields. The receiver
necessarily receives those bytes. Its decoder skips them without copying them
into an event, and clears the input buffer after processing. The experimental
command must not be used with real credentials until the Linux trial confirms
the protocol and the synthetic secret-in-argv/cwd test on the target `runsc`
build. This does not prevent the Sentry or transport from seeing the fields.

## Controlled trial

Use a self-managed Linux node with containerd and a pinned `runsc` release.
Record the kernel, containerd, `runsc`, and node-agent versions and runtime
root. Check the selected point with `runsc trace metadata` on that build.
Configure the `Default` trace session before the sandbox starts using
`--pod-init-config`; attaching with `runsc trace create` after startup cannot
demonstrate that `container/start` was captured. Do not use `--force` to replace
another monitor's session.

The test input is:

```json
{
  "trace_session": {
    "name": "Default",
    "points": [{ "name": "container/start" }],
    "sinks": [{
      "name": "remote",
      "config": { "endpoint": "/run/kubescape/gvisor-events.sock" }
    }]
  }
}
```

Create a private directory owned by the receiver, such as
`/run/kubescape` with mode `0700`. The receiver refuses an existing socket
path. Obtain the *exact* container ID from the local runtime before starting
that container, then run:

```sh
go run ./cmd/gvisor-start-probe \
  --socket /run/kubescape/gvisor-events.sock \
  --container-id "$CONTAINER_ID"
```

The flag is a controlled-trial identity check, not a production runtime
inventory integration. Start the prepared sandbox only after the receiver is
listening. In the production integration, node-agent's runtime inventory must
perform this check. A start event from this probe is not evidence of an actor
or session identity.

Test a normal start, twenty repeated starts, two concurrent sandboxes, an
absent or restarted receiver, and a root and child container with a harmless
synthetic canary in argv and cwd. Check stdout, stderr, errors, and any saved
artifacts for that canary before sharing results. Compare the received starts
and IDs with containerd or CRI records. A connection close is a disconnected
source, not a verified sandbox stop. No network meaning is inferred here.

The package tests cover protocol parsing, identity mismatch, sensitive-field
discard, and a Linux socket exchange:

```sh
go test ./pkg/gvisor -count=1
```

Receiver callbacks receive the caller's cancellation context and must interrupt
blocking work when it is canceled. The probe uses a write deadline to interrupt
blocked pipe output on SIGINT or SIGTERM, allowing the receiver to finish and
remove its socket even if the output consumer stops reading. Tests in
`cmd/gvisor-start-probe` cover a full output pipe and ordinary JSON output;
receiver tests also cover draining a closed event queue in order.
The probe restores stdout's original file flags on both normal and error exits,
so a parent process sharing the inherited pipe or terminal keeps its prior mode.
If output fails, the probe stops collection, reports the first write error on
stderr, and exits with status 1. Signal cancellation of a blocked write remains
a normal exit. Actual-process tests cover a closed output reader as well as
flag restoration and signal cancellation.

This document records the procedure. See the
[local ARM64 trial results and limits](experiments/gvisor-start-20261026/README.md)
for live containerd/runsc evidence. A comparison using node-agent itself remains
outstanding; the existing
[gVisor proof of concept](https://github.com/yellow-forrest/gvisor-visibility-poc)
is useful prior work but is not validation of this receiver.

## Repeated and concurrent starts

The probe accepts repeated `--container-id` flags. Each value is matched in
full, never as a prefix. The original single-ID invocation still works.
Obtain all IDs from the local runtime before starting the selected containers.
Reuse the receiver-owned `/run/kubescape` directory (mode `0700`) and the
trace configuration from the controlled trial above. The sink endpoint, probe
and readiness check all use `/run/kubescape/gvisor-events.sock`; `TRIAL_DIR`
stores evidence only. If you choose a different socket, replace that literal
with the same absolute path in all three places. JSON does not expand shell
variables, so the trace configuration must contain the actual pathname.

Create a private evidence directory before redirecting output:

```sh
umask 077
TRIAL_DIR="$(mktemp -d)"
./gvisor-start-probe \
  --socket /run/kubescape/gvisor-events.sock \
  --container-id "$CONTAINER_A" \
  --container-id "$CONTAINER_B" \
  > "$TRIAL_DIR/starts.jsonl" 2> "$TRIAL_DIR/probe.stderr"
```

Run the following readiness check in a second terminal while the probe runs.
Socket existence alone is not readiness: the receiver binds the path
before calling `listen`. Before starting either container, require a successful
connection and version-1 handshake with a bounded retry, for example:

```sh
python3 - /run/kubescape/gvisor-events.sock <<'PYREADY'
import socket
import sys
import time

deadline = time.monotonic() + 5
while time.monotonic() < deadline:
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
        connection.settimeout(0.2)
        try:
            connection.connect(sys.argv[1])
            connection.sendall(b"\x08\x01")  # Version-1 protobuf handshake.
            if connection.recv(32) == b"\x08\x01":
                break
        except OSError:
            pass
    time.sleep(0.05)
else:
    raise SystemExit("receiver readiness handshake timed out")
PYREADY
```

The check closes its connection without sending a start and produces no trial
event. Abort the trial if the check fails. It only establishes that the receiver
answered; keep checking that the probe is running while the workload starts.
Stop it with SIGTERM after the workload and wait for a zero exit status before
checking artifacts. A nonzero exit invalidates that run.

For twenty repeated starts, either collect each independently created ID in
advance and repeat the flag for every ID, or run separate probe invocations
and combine only the sanitized start JSONL files. Keep a runtime-derived
expected-count manifest for exactly those invocations. For the concurrent
case use one receiver with two IDs, overlapping sandbox lifetimes, and runtime
records that demonstrate the overlap. Two sequential starts are not evidence
of concurrency. The ID flag remains a manual trial allowlist; it does not
implement the production runtime inventory join.

## Check retained evidence

Use Python 3.9 or newer. Create `expected.json` from independently recorded
runtime starts, not from the probe output. Its keys must be exact runtime IDs
and its values the expected number of starts. For example, replace these
placeholders with the two real IDs:

```json
{"exact-runtime-id-a": 1, "exact-runtime-id-b": 1}
```

Use a harmless marker matching `[A-Za-z0-9_-]{16,}`, such as
`GVS_TRIAL_CANARY_2026`, in the root and child container argv and cwd fixtures.
Only ASCII letters, digits, underscores and hyphens are accepted, so ordinary
JSON string encoding leaves the marker literal. Quotes, backslashes, whitespace
and non-ASCII markers are rejected before reading evidence. Do not use real
credentials. After the probe has stopped, check each run:

```sh
python3 scripts/check-gvisor-start-trial.py \
  --expected "$TRIAL_DIR/expected.json" \
  --events "$TRIAL_DIR/starts.jsonl" \
  --canary GVS_TRIAL_CANARY_2026 \
  --artifact "$TRIAL_DIR/probe.stderr"
```

Repeat `--artifact` for additional retained logs or exports. The checker
rejects missing or excess start counts, unknown identities, unexpected event
fields, invalid
source/timestamps, blank JSONL records, nonzero sender-reported drop counts,
and the canary in the specified artifacts. Each input file is limited to
16 MiB. It prints neither
input records nor parser error payloads. It does not inspect unspecified
files, prove that the canary was actually used, verify the manifest's origin,
measure local queue drops, or prove runtime identity from a JSON file. JSON
record counts cannot prove timing, concurrency, or per-connection isolation.
If a manifest expects two starts for one ID, two identical records satisfy that
count; the checker does not authenticate events or distinguish replayed copies
from distinct starts. Independent runtime evidence is still required.
A passing check is an artifact consistency check, not a lifecycle integration
gate or proof that application code executed.

Fill in [the trial record](gvisor-start-trial-record.md) with version details,
runtime ground truth, privacy checks, host eBPF observations, and limitations.
Keep the synthetic fixture separate from sanitized evidence. Debug/strace
output can itself include argv or cwd; inspect it privately and sanitize it
before retaining or sharing. The checker can detect a known marker, not every
possible secret or encoding. A failed privacy check means the artifacts must
not be published.

The checker can be tested without `runsc`:

```sh
python3 -m unittest discover -s scripts -p test_check_gvisor_start_trial.py
```
