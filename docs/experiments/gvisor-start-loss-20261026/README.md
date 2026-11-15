# gVisor start-loss investigation, 26 October 2026

This follows [the live experiment in #1051](https://github.com/kubescape/node-agent/pull/1051).
That experiment retained a 19/20 run. This change adds receiver diagnostics,
fixes a reproduced loss mechanism, and repeats the real runsc trials.

**The historical missing start is still unexplained.** The original run has
no interrupted-read counter or complete runtime timeline. The controlled
reproduction below establishes a receiver defect, not its responsibility for
that earlier miss. Complete lifecycle coverage and production integration
remain unproven.

## Confirmed failure and fix

The receiver used `SO_RCVTIMEO` and treated `EINTR` from `Recvmsg` as a fatal
connection error. On Linux, timed socket reads can return `EINTR` even with
`SA_RESTART`, as described in [signal(7)](https://man7.org/linux/man-pages/man7/signal.7.html).
An interruption could therefore close a valid trace connection before its next
start arrived.

The controlled test starts the actual probe, completes its version-1 handshake,
sends SIGURG to the probe's threads, and then sends a synthetic valid start for
an allowlisted ID. It uses no real credentials and retains no raw protobuf.

| Build | Send result | Retained starts | Interrupted reads | Read errors |
|---|---|---:|---:|---:|
| Before fix, diagnostic counters added | BrokenPipeError | 0 | 1 | 1 |
| After fix | Sent | 1 | 10 | 0 |

The [before](evidence/signal-before/health.jsonl) and
[after](evidence/signal-after/health.jsonl) counters are retained alongside
stdout. The before build is the pre-fix receiver with the same counter
instrumentation, not an unmodified release. SIGURG is controlled fault
injection, not evidence of a signal in the historical failed run.

The receiver now retries interrupted reads, checks cancellation, and preserves
an absolute handshake deadline under repeated signals. It also retries an
interrupted handshake response. Idle reads retain a two-second cancellation
polling bound. No decoder, resolver, runtime trace configuration or normal
node-agent startup is changed.

## Fresh real runsc trials

| Trial | Expected / received | Read errors | Queue drops | Frames reporting sender drops |
|---|---:|---:|---:|---:|
| [Fixed run 1](evidence/fixed-run-1/ledger.json) | 20 / 20 | 0 | 0 | 0 |
| [Fixed run 2](evidence/fixed-run-2/ledger.json) | 20 / 20 | 0 | 0 | 0 |

Both runs used exact containerd IDs recorded before task startup. The workload
and argv/cwd privacy canary are the earlier experiment's fixture. Both pass the
existing offline count/privacy checker, including stderr and the incremental
runtime ledger as additional artifacts. No literal canary occurs in the
retained evidence. Neither live run observed an interrupted read. Forty
successful starts are bounded evidence, not proof of reliable delivery.

Environment: the same dedicated Ubuntu 24.04.5 ARM64 VM, kernel
6.8.0-147-generic, four vCPUs, 6 GiB RAM, runsc release-20261019.0 with systrap,
containerd 2.2.1 and runc 1.3.4 as the earlier report. Fixed run 1 predates a
minor handshake counter cleanup; fixed run 2 uses the final production source
in this change. The read retry implementation is identical in both.

## Reproduce

Use only the dedicated disposable VM described in the previous experiment.
Build the probe from this branch and retain its source version and checksum.

1. Copy the earlier `trial.py` to `/home/ubuntu/gvisor-trial/trial-helpers.py`.
   Use the repository version with its `if __name__` guard, so importing does
   not execute a trial. Keep the earlier rootfs and runsc configuration.
2. Place the fixed probe at `/home/ubuntu/gvisor-trial/gvisor-start-probe-fixed`.
   Recreate `/run/kubescape` as a root-owned directory with mode 0700 after a
   VM reboot. Sink and receiver must use the same socket path.
3. Run `sudo python3 repeat-diagnostics.py fixed-run-1`, then repeat with a
   fresh output name. The fixture refuses to overwrite evidence and records
   the runtime ledger after each start.
4. For controlled signal injection run
   `sudo python3 interrupted-read.py --probe /absolute/path/to/probe --output /absolute/new/output-directory`.
   This synthetic test validates transport behavior, not runtime identity.
   The pre-fix diagnostic build is not committed as a second implementation.
5. Run the repository evidence checker against each expected manifest and
   JSONL file, with stderr and ledger as additional artifacts and the earlier
   fixture's synthetic canary. Preserve failures and sanitize before sharing.

## Validation boundaries

The focused packages were cross-compiled with cached Go 1.26.8 and their pinned
direct dependencies (x/sys v0.48.0 and protobuf v1.36.12) in an isolated module.
The main module requires Go 1.27. No dependency files were changed, and this is
not a full main-module build. Linux receiver tests, focused probe tests, Linux
vet, the evidence checker and its 14 unit tests were run. Actual-process probe
tests that invoke a Go compiler and the full repository suite were not run in
the VM. No managed GKE or x86_64 trial was performed.

The new counters contain no IDs, argv, cwd or message bytes. They help separate
handshake/read failures, invalid frames, unresolved IDs, sender loss reports and
local queue loss. They do not authenticate a sender or prove completeness.
Start still precedes application execution; socket closure is not a stop.

## Node-agent comparison: attempted, inconclusive

**27 October follow-up:** the empty exec counts below came from a default
LIST response, which omits profile bodies. They do not establish that stored
profiles lacked exec observations. The [individual-GET comparison](../gvisor-profile-comparison-20261027/README.md)
corrects the query and records fresh controls. The original summary is retained
as historical evidence of the query used at the time.

A separate K3s v1.37.1+k3s1 cluster in the same VM ran the official
`quay.io/kubescape/node-agent:v0.3.293` image with chart 1.40.5. This is the
released node-agent's observation path, not this receiver integrated into it.
The agent became Ready and logged startup of its exec/open/fork/exit tracers.
Both controlled Pods started afterward and exited 0. Their exact containerd
records confirm `io.containerd.runc.v2` and `io.containerd.runsc.v1` respectively.
Both ran three `/bin/busybox true` commands after a 20-second delay.

The ordinary workload produced a completed ContainerProfile with no retained
exec records; the gVisor workload had no ContainerProfile in the final query.
See the [sanitized summary](evidence/node-agent-comparison.json).
**The ordinary positive control failed, so this does not establish an exec
visibility difference.** Tracer startup and Pod success alone are insufficient.
The cause could lie in collection, identity enrichment, profile handling or the
test configuration; this trial does not distinguish them. The comparison gate
remains open and is not replaced by the earlier successful bpftrace comparison.

The [workloads](comparison-workloads.json) and [initial Helm values](comparison-values.yaml)
are retained. To repeat on a disposable cluster with the earlier runsc shim:

1. Install K3s and configure a `runsc` containerd runtime using
   `io.containerd.runsc.v1` and a runsc config containing `platform = "systrap"`.
   This comparison does not enable the SecCheck sink. K3s uses its own
   `/run/k3s/containerd/containerd.sock`; it is separate from the lifecycle
   trials' containerd service.
2. Install chart 1.40.5 with the retained values. The test image was explicitly
   overridden to node-agent v0.3.293. Set its IG config at `/root/.ig/config.yaml`
   to `containerd-socketpath: /run/k3s/containerd/containerd.sock`, using a
   ConfigMap mounted with subPath. Host `/run` must be accessible to the agent.
3. In the node-agent config, change `initialDelay` from `10m` to `5s` and set
   `hostSensorEnabled` to false, then restart the DaemonSet. The initial values
   alone do not apply these later test adjustments.
4. The initial storage v0.0.348 container failed before starting its process.
   In this VM its image root had mode 0700. For this disposable test only,
   storage was changed to UID/GID 0, `runAsNonRoot: false`, and command
   `/usr/bin/storage`. This is an environment workaround, not a proposed chart
   change or production deployment recommendation. Its root-directory cause
   was not independently established beyond the observed permissions.
5. Wait for storage and node-agent readiness and tracer startup, then apply the
   workload file. Verify containerd runtime names independently, wait for both
   Pods to finish, and query `containerprofiles` in `gvisor-comparison`.
   Do not interpret missing gVisor execs unless the ordinary positive control
   actually retains the expected observations.

The summary exports no profile argv, credentials, kubeconfig or service-account
tokens. The local comparison installation is experimental, including the
chart/image version combination and the storage workaround. A clean positive
control on an agreed supported deployment is still required before integration.
