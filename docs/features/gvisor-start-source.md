# Experimental gVisor start observations

This opt-in source joins SecCheck `container/start` claims to the node's local
CRI inventory and Kubernetes API before exporting an observation. It runs in
the Kubernetes node-agent entrypoint, separately from the host eBPF watcher.
It does not add an exec event, ContainerProfile entry, rule alert or stop event.

The source is disabled by default. It remains an experimental integration:
complete lifecycle delivery, source-health metrics, fairness under load and
managed GKE support have not been established. The earlier unexplained missed
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

The receiver retains its eight-connection and 128-event queue bounds. RPCs
honor cancellation, idle socket reads retain the two-second polling bound,
and the source finishes before the existing OTEL shutdown flush. Cancellation
can discard queued starts whose identities can no longer be checked. This PR
does not claim complete queue/export-loss accounting or automatic source restart;
collector-health reporting and recovery remain the next planned work.

See the [live integration report](../experiments/gvisor-start-integration-20261102/README.md)
for actual node-agent-to-OTLP evidence and its limitations.
