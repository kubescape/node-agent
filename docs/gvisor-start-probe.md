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

This document records the procedure, not results. Live `runsc` and node-agent
host eBPF observations must be added after the Linux trial; the existing
[gVisor proof of concept](https://github.com/yellow-forrest/gvisor-visibility-poc)
is useful prior work but is not validation of this receiver.
