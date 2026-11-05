# Experimental gVisor start observations

This opt-in source joins SecCheck `container/start` claims to the node's local
CRI inventory and Kubernetes API before exporting an observation. It runs in
the Kubernetes node-agent entrypoint, separately from the host eBPF watcher.
It does not add an exec event, ContainerProfile entry, rule alert or stop event.

The source is disabled by default. It remains an experimental integration:
complete lifecycle delivery, fairness between sandboxes and managed GKE
support have not been established. The earlier unexplained missed
start is not retrospectively explained by this integration.

## Configuration

Add to the node-agent JSON configuration only on a self-managed test node:

```json
{
  "gVisorStart": {
    "enabled": true,
    "socketPath": "/run/kubescape/gvisor-events.sock",
    "runtimeEndpoint": "/run/containerd/containerd.sock",
    "runtimeHandler": "runsc"
  }
}
```

`runtimeEndpoint` is an absolute local Unix socket path. When omitted, the
node-agent uses its detected runtime socket. For K3s this is normally
`/run/k3s/containerd/containerd.sock`. The implementation supports CRI v1 and
complete 64-character lowercase hexadecimal container/sandbox IDs, as used by
the tested containerd setup. Docker sockets and TCP endpoints are not supported.

`runtimeHandler` defaults to `runsc`. It must name the handler that actually
runs gVisor on the node. The operator configures that mapping; the handler's
name alone is not independent verification of the installed runtime binary.

The socket parent must already exist, be private (mode 0700) and belong to the
node-agent's effective UID. The listener creates its socket with mode 0600 and
never replaces an existing socket. No runsc control-root access is added.
The application sandbox must not be given access to the host listener.

The existing OTLP **log** exporter must be configured and initialized, for
example with `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`. A general
`OTEL_EXPORTER_OTLP_ENDPOINT` also configures logs through the existing provider.
A stdout alert exporter or a metrics-only endpoint does not export these
observations. Initialization does not prove the collector is reachable.

Configure runsc's `Default` trace session before workload startup using the
[existing trace configuration](../gvisor-start-probe.md). Enable only
`container/start`, with no optional fields, and use the same absolute socket
path in the sink and node-agent. This code does not install runsc, create trace
sessions or overwrite another monitor's session. No Helm templates change here.

After node-agent startup, require a successful bounded version-1 seqpacket
handshake before starting the experimental workloads. Kubernetes readiness
alone does not indicate that the optional source successfully bound its socket.

## Identity and privacy boundary

The receiver still discards Sentry `Args` and `Cwd` before queueing or export.
Disabling optional fields does not prevent their receipt over the socket.
The raw input buffer is cleared by the existing decoder/receiver path.

For each claimed ID, the integration:

1. Queries CRI `ListContainers` with that ID and requires exactly one complete
   matching ID, in CREATED or RUNNING state. A prefix match is rejected.
2. Queries that container's sandbox status, requiring the exact sandbox ID,
   READY state, configured runtime handler and complete Pod metadata.
3. Fetches the Kubernetes Pod and verifies namespace, name, UID, node assignment
   and container membership. Namespace/name/label exclusions use the existing
   `IgnoreContainer` policy, including dynamic namespace selection when enabled.
4. Repeats the join immediately before export. It does not carry a stale identity
   cache across container removal. Containers disappearing between these joins,
   or lookups that time out, are deliberately not attributed.

Each join has a two-second context deadline shared by the CRI and Kubernetes
requests. A private CRI client belongs to the optional source; shutdown never
closes the host watcher's runtime client. The CRI responses request no verbose
runtime details and retain only allowlisted identity fields.

An inventory match verifies the claimed ID and its metadata. It does **not**
authenticate which Sentry sent a frame or attest to application execution.
There is no per-actor/session attribution, Sandbox CRD/WorkerPool mapping, Sentry
PID relabeling or syscall inference. Sandbox/pause starts whose IDs are not
CRI application-container IDs remain unresolved and are not exported.

## Export contract

The existing OTEL log provider emits an INFO `RuntimeObservation` record with:

- `source=gvisor_trace`, `kind=container_started`, `identity_status=verified`;
- `identity_origin=local_cri_and_kubernetes` and the receiving `node`;
- `container.id`, `sandbox_id`, `runtime_handler`;
- `namespace`, `pod_name`, `pod_uid`, `container_name`;
- `sender_reported_drops`, the connection's cumulative sender-reported count.

The record timestamp and observed timestamp are the receiver's observation
time, not a source execution timestamp. Zero sender drops do not account for
entirely missing events or local/exporter loss. The OTEL batch processor provides
a bounded export path; submission is not an acknowledgement of delivery.
There is no added stdout/syslog/alert-HTTP representation of this event.

## Failure and shutdown

Invalid configuration, unavailable CRI or missing OTLP log setup produces a
warning that visibility is degraded; ordinary node-agent collection continues.
A receiver failure also logs a fixed warning without Sentry/CRI payloads. It
does not synthesize a stop. No start observations is not evidence of no starts.

The receiver retains its eight-connection and 128-event shared queue bounds.
Each connection may occupy at most 16 queued entries, so a flooding connection
cannot consume the entire queue while other established senders are active.
The callback remains serial and FIFO, with a two-second deadline per identity
join. This is bounded admission fairness between connections, not authenticated
per-sandbox fairness. A sender opening multiple connections or reconnecting
repeatedly can consume more capacity; no claim of adversarial fairness is made.
A short burst from a single connection can now drop after its 16-entry quota,
even when the shared queue has space. These drops are included in `queue_drops`.

An accepted connection is not necessarily handshaken or producing events. An
idle client that does not complete its handshake is closed after two seconds.
A broken/malformed connection does not stop the listener; senders can reconnect
and perform a new version-1 handshake. Connections beyond the eight-client bound
are closed and counted. An idle established connection is not treated as a
container stop or an automatic reason to restart a trace session.

Listener failures retry after 1, 2, 4, 8, 16, then at most 30 seconds, until
shutdown. Every failed attempt increments `listener_failures`; retries never
unlink an existing path, replace another listener or claim runsc's trace session.
After an operator removes a conflicting path or restores the private parent,
the next retry can bind. The source does not reconnect the sender, replay missed
starts or recover an event lost before receipt. Initial CRI/exporter setup
failures still require operator correction and a node-agent restart. Transient
lookup failures reject that start; subsequent frames can succeed without
restarting the listener.

RPCs honor cancellation and idle socket reads retain the two-second polling
bound. On cancellation, queued starts are counted as `canceled_starts` rather
than dispatched to callbacks with a canceled context. An already running
callback may instead increment `recheck_rejected` if its identity lookup is
interrupted. Internal listener errors drain queued work while the caller's
context remains active. The source finishes before the existing OTEL flush.

## Collector health and loss accounting

While enabled, the integration submits an INFO `RuntimeSourceHealth` log every
30 seconds and a final snapshot on shutdown, through the existing OTLP log
provider. No additional endpoint, metric series, configuration or permissions
are introduced. Reports contain `source=gvisor_trace`, a fixed state and numeric
counters, with no workload identities, raw frame data, argv, cwd or error bodies.
Counters accumulate for this collector instance and reset on process restart.
Snapshots read fields independently, so equations below apply after collection
stops, not necessarily during concurrent activity.

States describe only local collection:

- `retrying_listener`: the enabled collector is attempting to bind or waiting
  before another attempt;
- `listening`: the socket is listening, with no accepted clients currently active;
- `connected`: at least one accepted client exists, possibly still handshaking;
- `stopped`: the collector has finished.

None of these states proves that runsc tracing is configured, that all sandboxes
are connected, that a workload executed, or that an OTLP collector received data.
A disconnected trace socket is a source-health signal, never a container stop.

The report preserves the receiver diagnostics: `active_connections`,
`accepted_connections`, `closed_connections`, `rejected_connections`,
`handshakes`, `handshake_errors`, `received_frames`, `read_errors`,
`interrupted_reads`, `invalid_frames`, `unresolved_starts`, `ignored_frames`,
`verified_starts`, `callbacks_completed`, `sender_drop_frames`, and `queue_drops`.
It adds `canceled_starts`, `recheck_rejected`, `export_submitted`, and
`listener_failures` to describe where starts leave this pipeline:

- `verified_starts` is the receiver's successful initial admission, before its
  second identity check. It equals `queue_drops + canceled_starts +
  callbacks_completed` after all workers finish.
- `callbacks_completed` equals `recheck_rejected + export_submitted` for the
  integration. Recheck rejection includes expired/missing identities, policy
  exclusions, lookup failures and cancellation during dispatch. Initial failures
  remain in `unresolved_starts`; neither count distinguishes these reasons.
- `export_submitted` means the nonblocking OTEL emit call returned. It is not
  remote delivery or acknowledgement. Exporter queue loss and transport failure
  are outside these receiver counters and require the existing OTEL diagnostics.
- `sender_drop_frames` counts frames carrying a nonzero cumulative sender drop
  field. It is **not** a sum of dropped starts. Repeated cumulative values or
  reconnects must not be added as distinct lost events. Verified observation
  records retain the sender's original cumulative field for investigation.

There is no end-to-end loss percentage: events absent from the socket cannot
be counted, and the earlier missed start remains unexplained. A zero loss
counter or quiet source must not be interpreted as complete visibility.

The regression tests use local Linux seqpacket clients to exercise queue
pressure, cancellation, bad/oversized identities, connection saturation,
reconnects, listener retry and path cleanup. They validate local recovery and
accounting, not live runsc reconnect behavior or a new CRI/managed GKE trial.

See the [live integration report](../experiments/gvisor-start-integration-20261102/README.md)
for actual node-agent-to-OTLP evidence and its limitations.
