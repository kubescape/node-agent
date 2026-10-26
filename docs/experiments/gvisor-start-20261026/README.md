# Local ARM64 gVisor start experiment, 26 October 2026

This is a live containerd experiment following
[design #23](https://github.com/kubescape/designs-and-proposals/pull/23),
using the receiver from #1024 and trial tools from #1046.

**Integration decision: blocked by an unexplained missed start.** One repeated
run received 20/20 starts; the next received 19/20, missing
`gvisor-repeat-04`. Every retained event reported zero sender drops. Those
zeros do not account for an entirely missing event or unmeasured local loss.
This evidence does not establish complete lifecycle coverage.

## Results

| Case | Observed result | Evidence |
|---|---|---|
| Repeated starts, run 1 | 20/20 received | [run 1](evidence/run-1/repeated.jsonl) |
| Repeated starts, run 2 | 19/20; repeat-04 missing | [failed run](evidence/run-2-missed-start/repeated.jsonl) |
| Repeated starts, run 3 | 20/20 received | [runtime ledger](evidence/run-3/results.json) |
| Concurrent sandboxes | 2/2 in both completed runs; run 3 records both RUNNING together | [runtime ledger](evidence/run-3/results.json) |
| Root and child | 2/2 with separate rootfs paths; no literal canary in retained output | [root/child output](evidence/run-3/root-child.jsonl) |
| Receiver absent | Container startup fails with missing sink socket | [failure results](evidence/run-3/failure-results.json) |
| Receiver restarted | Existing task remains running; new task produces a new start; no existing-start replay in the observation interval | [failure results](evidence/run-3/failure-results.json) |

The offline checker passes seven case files and fails the missed-start case,
as recorded in [checker results](evidence/checker-results.json). Keeping a
failed check is intentional. All exported artifacts were separately scanned
for the literal canary before publication. Raw protobuf frames, argv/cwd,
full OCI specs and unsanitized runtime logs are not included. Trailing blank\nlines were removed from the host-bpftrace text output.

A restarted receiver accepting a new sandbox does not establish recovery of
the existing trace connection. The restart test does not replace the Default
session or infer a stop from disconnection.

## Environment

The host is an Apple Silicon Mac; the tests run inside a dedicated Multipass
VM, not against macOS's kernel.

| Component | Recorded value |
|---|---|
| Guest | Ubuntu 24.04.5 LTS, aarch64 |
| Kernel | 6.8.0-147-generic |
| Allocation | 4 vCPUs, 6 GiB RAM, 32 GiB virtual disk |
| gVisor | `release-20261019.0`, systrap |
| containerd | 2.2.1 |
| Ordinary runtime | runc 1.3.4-0ubuntu1~24.04.1 |
| Rootfs | busybox-static 1:1.36.1-6ubuntu3.1 |
| Host trace tool | bpftrace 0.20.2 |
| Source checkout | node-agent `1051d7b7366c23606605dfb05f22962746855b6c` |
| Probe compiler | Go 1.26.8, CGO disabled, linux/arm64 |
| Direct dependencies | x/sys v0.48.0, protobuf v1.36.12 |

The probe and focused Linux tests were built from an isolated copy of the
merged `pkg/gvisor` and `cmd/gvisor-start-probe` sources with their pinned direct
dependencies. The main module requires Go 1.27; this was not a full main-module
build with that toolchain. Repository dependency files were not changed.

| Artifact | SHA-256 |
|---|---|
| Official gVisor ARM64 archive | `5790f89dc94b091b5aa0f0b6596aa4391606b3fe5f069e68f440576f3388abd8` |
| Installed runsc | `c771292129c7ff96e83c5074485e3d33cfc938652dc70682bb792a66842d4de2` |
| Probe | `f0812b12ee5488d29fecf22f20b147618889d1c3ebbcf5bcce860a61c877ebef` |
| BusyBox | `52151e7f322f926b64049cdaa1410dc3ea6485525e0624b05813791c219ae933` |

The archive was checked against its release's SHA256SUMS before extraction.
`runsc trace metadata` listed `container/start`. No optional fields were enabled.

## Method and privacy

The VM has no other container workloads. The fixture uses the `gvisor-trial`
containerd namespace and a private root-owned directory at `/run/kubescape`.
Sink and receiver use `/run/kubescape/gvisor-events.sock`, with a bounded
seqpacket readiness handshake before startup.

Container records are created first; their exact IDs and runtime names are
checked via `ctr containers info` before supplying the probe allowlist and
starting tasks. This is controlled inventory correlation, not the production
resolver or authentication of an arbitrary sender. No Pod, Sandbox CRD,
WorkerPool, actor or session metadata is attached.

The harmless `GVS_TRIAL_CANARY_2026` fixture appears in argv and cwd. Its
presence in fixture source is intentional; it must not appear in retained
receiver stdout, stderr or sanitized results. Root and child containers need
different rootfs paths: reusing a rootfs inside one sandbox initially failed
with gVisor's "mount source already has a filestore file" error. The corrected
fixture copies the child rootfs before sandbox startup.

The initial harness stopped on a count mismatch and lost its in-memory timing
ledger on that failure path. The missed run retains its expected manifest and
19 actual records; it is not a complete runtime timeline. The recorded fixture
now saves inventory and start results incrementally and preserves count failures.

## Host eBPF comparison

The same workload invoked `/bin/busybox true` three times under runc and gVisor.
A host `sys_enter_execve` bpftrace program filtered that exact pathname without
retaining arguments.

| Runtime | Requested guest exec calls | Matching host observations |
|---|---:|---:|
| Ordinary runc | 3 | 3 |
| gVisor systrap | 3 | 0 |

Both tasks started successfully and were observed stopped afterward. This is
one narrow host tracepoint comparison, not proof that the host sees no gVisor
activity and not a node-agent exporter or Kubernetes test.

## Reproduction

Use a disposable Ubuntu ARM64 VM with sudo access. These scripts change VM
packages, `/usr/local/bin` and fixed trial paths; do not use a shared node.

1. Run `sudo sh bootstrap.sh` in the VM. It pins and verifies the gVisor archive.
   Ubuntu package versions can change; record differences from the table above.
2. Build/install the probe at `/usr/local/bin/gvisor-start-probe`. For the isolated
   build used here, copy the two source directories and `go.sum` into a temporary
   module named `github.com/kubescape/node-agent`, declare Go 1.26.0 and the two
   direct dependencies above, and use Go 1.26.8 with
   `GOTOOLCHAIN=local GOOS=linux GOARCH=arm64 go build -mod=mod -o gvisor-start-probe ./cmd/gvisor-start-probe`.
   Record the compiler/source versions if using another build.
3. Place the Python fixtures in `/home/ubuntu/gvisor-trial`. Run
   `sudo python3 /home/ubuntu/gvisor-trial/trial.py` with the evidence directory
   absent. Existing evidence is not overwritten.
4. After the lifecycle fixture finishes, run
   `sudo python3 /home/ubuntu/gvisor-trial/failure-trials.py` for the receiver
   restart check, then run
   `sudo python3 /home/ubuntu/gvisor-trial/bpf-baseline.py` with the namespace idle.
5. Check each expected/JSONL pair using `scripts/check-gvisor-start-trial.py` with
   probe stderr as an additional artifact and `--canary GVS_TRIAL_CANARY_2026`.
   Preserve failures, rather than discarding runs that do not pass.
6. Inspect the trial namespace's tasks/containers after cleanup and save sanitized
   evidence before stopping the VM.

These are experiment fixtures, not a general installer or node-agent collector.
Tracing is configured before task startup, without `--force` or replacing another
monitor's session.

## Validation scope and follow-up

The Linux receiver package's seven tests and four probe tests (ID matching,
invalid IDs, full-pipe cancellation and normal output) passed inside the VM.
Test binaries were cross-compiled using the isolated build above. The
actual-process flag-restoration test, which invokes a Go compiler, was not run
there. The 14 Python evidence-checker tests passed on the host.

The cause of the missing start remains unestablished. Investigate per-connection
health, sender counters while the sandbox is alive and local receiver loss before
attributing it to Sentry, transport, decoding, shutdown or output. A longer-lived
workload is a diagnostic comparison, not a substitute for explaining the miss.

Still outstanding: node-agent's own eBPF/exporter comparison, CRI/Kubernetes
metadata joining, live slow-consumer/fairness and loss testing, terminal-source
validation, network semantics, systematic overhead measurements, managed GKE and
x86_64 reproduction. Host bpftrace does not satisfy the node-agent comparison gate.
A socket close is not a verified container stop; a start precedes application
execution.
