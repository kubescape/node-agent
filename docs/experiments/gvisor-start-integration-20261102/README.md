# Node-agent gVisor start integration, 2 November 2026

This is a live trial of the rebuilt Kubernetes node-agent, following the
[profile comparison in #1053](https://github.com/kubescape/node-agent/pull/1053).
The receiver, CRI/Kubernetes identity join and existing OTLP log exporter run
inside the actual node-agent process. The standalone start probe is not the
producer for this evidence.

## Observed results

| Case | Expected observations | Received |
|---|---:|---:|
| Repeated application-container starts | 20 | 20 |
| Two overlapping gVisor workloads | 2 | 2 |
| gVisor workload in an excluded namespace | 0 | 0 |
| Valid synthetic frame claiming an unknown ID | 0 | 0 |
| Ordinary-runtime control | 0 | 0 |

All 24 workloads (22 accepted gVisor, one excluded gVisor and one ordinary)
completed with exit code 0. Each accepted container ID, sandbox ID, Pod UID,
Pod name/namespace, node and container name matched the independently queried
CRI/Kubernetes inventory. The concurrent workloads' execution intervals overlap.
There was exactly one retained observation per accepted container, and each
reported zero sender drops. These are bounded results, not delivery guarantees.

See the [verification](evidence/verification.json),
[identity ledger](evidence/runtime-ledger.json),
[received observations](evidence/observations.jsonl) and
[environment](evidence/environment.json). All records are marked
`source=gvisor_trace`, `kind=container_started`, `identity_status=verified`,
with `identity_origin=local_cri_and_kubernetes`.

The ordinary control produced no trace input naturally; runtime-handler
rejection is additionally covered by the CRI unit tests. The unknown-ID control
sends a valid remote-sink frame but does not establish a real runtime start.
The trial does not authenticate the sender or prove application execution from
the start record. Workload completion is separate runtime evidence.

## Privacy validation

The fixture puts the harmless marker `GVS_INTEGRATION_CANARY_2026` in both
argv and the OCI working directory. A mounted empty directory supplies that
working directory. The marker in fixture source is intentional.

The collector scans the complete incoming OTLP request for the literal marker
**before** filtering retained fields. It records a violation flag without
copying the offending payload. Every retained observation has
`wire_canary_found=false` and `unexpected_attribute_count=0`. A collector
regression test injects an extra sensitive attribute and proves that filtering
cannot falsely clear the wire check. The node-agent's ordinary logs were also
scanned locally and contained no literal marker; those raw logs are not included.
This checks the literal synthetic marker and the fixed export contract, not
every possible encoding of arbitrary credentials.

The published run repeats an initial successful 20-plus-two trial with the
stronger pre-filter wire check. The earlier run remains in the VM for audit;
only the final run is used in the table above.

## Environment

- Dedicated Ubuntu ARM64 Multipass VM, four vCPUs, 6 GiB RAM, kernel
  6.8.0-147-generic.
- K3s v1.37.1+k3s1, local CRI endpoint
  `/run/k3s/containerd/containerd.sock`, runsc release-20261019.0 with systrap.
- Node-agent built from this PR's working tree on base `0ad6adb2` using the
  repository's Go 1.27.0 toolchain and pinned dependencies, with CGO disabled.
  The actual binary SHA-256 is retained in the environment summary.
- The rebuilt binary was mounted into the existing official v0.3.293 test
  image and selected as its command. This is not a published image release.
- BusyBox is pinned by image-index digest in the fixture. Runtime image IDs
  are recorded per workload.
- Runtime detection, application-profile learning and host sensing were
  disabled for this source/export trial. The earlier eBPF comparison remains
  separate evidence; no guest-syscall comparison is inferred here.

The test retains the earlier experimental storage/cluster setup, including
its documented root storage workaround. It is not a production chart recipe.
No managed GKE or x86_64 claim is made.

## Reproduction

Use only the dedicated self-managed test VM and preserve the original
DaemonSet, ConfigMap and runsc runtime settings privately before changing them.
Do not export kubeconfig, service-account tokens, cloud credentials or raw OCI
specifications into a PR.

1. Build `./cmd` and `./docs/experiments/gvisor-start-integration-20261102/otlp-capture`
   for Linux ARM64 with Go 1.27.0. Install the test binary into the experimental
   node-agent Pod using a read-only hostPath mount and command override. Keep
   the existing image's gadget data and host mounts. Record the binary hash.
2. Run the capture utility on a trusted VM-local address with a new output
   file. Set `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` on node-agent to that collector.
   The plaintext transport used for this isolated local experiment is not a
   public collector deployment.
3. Enable the [source configuration](../../features/gvisor-start-source.md),
   with the K3s CRI endpoint, `runtimeHandler=runsc` and
   `/run/kubescape/gvisor-events.sock`. Keep namespace selection limited to
   `gvisor-comparison`. Create the root-owned socket directory with mode 0700.
4. For newly created gVisor Pods only, configure runsc's pod-init configuration
   with the existing `container/start` remote sink pointing to that same
   socket. Do not overwrite another monitor's Default session. This experiment
   owns its runtime settings and newly created sandboxes.
5. Put the fixtures and binaries in
   `/home/ubuntu/gvisor-trial/integration-20261102`. Start the collector with
   `--output` pointing to `observations.jsonl` there. Wait for agent startup
   and a successful version-1 seqpacket handshake, then run `trial.py --output`
   with the `evidence` subdirectory as its new output path. It performs 20
   repeated starts and the unknown-ID/ordinary controls.
6. Run `parallel-trial.py`, then `verify.py` before deleting Pods. Verification
   checks every export against retained Pod and CRI identities, exact counts,
   concurrent execution overlap, the pre-filter privacy flags and local agent
   log scan. An error is a failed experiment, not evidence of no starts.
7. Export only the sanitized observation/verification files. Restore the
   original ConfigMap, DaemonSet and runsc settings, remove only the experiment
   workloads, allow the OTEL shutdown flush, then stop the collector and VM.
   Do not delete the broader `kubescape` namespace.

The fixtures use fixed trial names and refuse to overwrite result directories.
Use fresh names/directories or explicitly archive and clean up a previous
experiment before repeating. Kubernetes/CRI errors and OCI specifications can
contain the marker; the fixtures do not retain those raw responses as evidence.

## Validation and remaining limits

The Linux ARM64 node-agent built successfully. Focused Linux tests passed for
receiver/integration behavior, CRI verification, Kubernetes UID/node/filter
checks, opt-in config and the distinct OTEL record contract. Linux-targeted
vet passed for the changed packages. Portable CRI and OTEL tests also passed
with race detection on macOS. The capture privacy regression and the existing
22 Python gVisor-tool tests passed. This was not the full repository suite or
a Linux race run.

The previously unexplained 19/20 start run is not retrospectively explained.
This source remains experimental and disabled by default. It can miss very
short-lived containers during identity rechecks, discard queued starts on
cancellation, or lose records through the bounded OTEL batch exporter. Detailed
health metrics, fair buffering, reconnect/recovery policy, overhead benchmarks,
stop semantics and network signals remain follow-up work. There is no actor or
session attribution and no claim of in-sandbox behavioral enforcement.
