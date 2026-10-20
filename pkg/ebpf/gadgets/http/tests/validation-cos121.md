# COS 121 verifier validation — 2026-10-16

Validated PR #1012 production source at `d448cce61d763ed4bccd537d15fb8c1248bed166`
against its base `67e455e040520a3f1f5a4ac20fbf5fe25f676d43`.

## Environment and identity

All execution was local on an x86_64 workstation using KVM/QEMU, four vCPUs
and 4 GiB RAM. The guest reported:

- COS `VERSION_ID=121`, `BUILD_ID=18867.624.2`.
- `6.6.157+ #1 SMP Sat Sep 26 10:00:07 UTC 2026 x86_64`.
- Vendor Docker `27.5.1`; IG `v0.48.1`.

Source payload: `https://storage.googleapis.com/cos-tools/18867.624.2/cos_full_payload_stable.bin`.
Payload MD5 (base64): `hl91B9GxQQ/T4mZr/MJNGg==`. Extraction checked individual
operation hashes and final partition SHA-256 values:

| Partition | SHA-256 |
| --- | --- |
| root | `77fb2cb94838dbb12c5585ff2d6e77474541804e772ff69a6456ca193d648e26` |
| kernel | `e821cec8c0beb62b2b4ea61bc63afbdce7449b9634e0bd791bd4b28edda4bc14` |

The original vendor kernel was unpacked without recompilation or patching.
The original root partition was mounted read-only beneath a writable overlay.
A BusyBox initramfs loaded the vendor virtio block module and launched a test
shell instead of COS systemd. The guest mounted proc/sys/dev, bpffs, debugfs,
and cgroup2; Docker used vfs storage with bridge/iptables management disabled.
Python and IG ran in a privileged container with guest host PID/network access.
The kernel command line was `console=ttyS0 rdinit=/init panic=-1`.
These boot/runtime differences are explicit: this is exact vendor kernel/rootfs
validation, not a normal GCE boot or a full host-agent deployment.

## Requested evidence

| Run | Result |
| --- | --- |
| Baseline ELF load | Rejected in `syscall__probe_ret_sendmsg`, with `invalid access to map value, value_size=32768 off=0 size=262144`; exit 1 |
| Patched load and capture | All 42 live TCP scenarios passed; exit 0 |
| Patched detach/reattachment | Separate tracer process using identical artifact; all 42 scenarios passed; exit 0 |

The baseline amd64 ELF was exactly 326,256 bytes with SHA-256
`d278a0cf36ffcd8e95dad1b97da80422ba2e9c7d92342da4b9ff1857baa1151d`,
matching issue #1009. The baseline OCI index was a local rebuild, **not** the
released OCI index; identity equivalence is established for the ELF bytes.
Patched amd64 SHA-256:
`ed3cc0343a3784f60be408be1f6f923386b41f1f432a3c285c89d1e28007eff3`.
Patched arm64 SHA-256:
`3f5b58c7263385ee64f57b2a63d95045cc62788c22216c5c8e91aecc1cd84192`.

Capture tested sendmsg, recvmsg, writev and readv; sizes immediately below,
at and above 16 KiB and 256 KiB; split/empty vectors and partial receives.
The existing runner checked payload bytes and chunk/syscall limits. Both
architectures compiled and retained direct size/capacity checks before helper
112. arm64 was not loaded on hardware.

## Repository checks

Before the upstream merge, after rebuilding `tracers.tar`, the full default Go suite,
HTTP race tests, vet for HTTP/containerwatcher, and Linux amd64 agent build
passed with Go 1.27.0. The pre-existing archive had an incompatible trace_open
schema; rebuilding resolved `TestOpenFields` without changing its expectations.
The unit command was:

```sh
env TMPDIR=/home/linux/.cache/http1009/tmp \
  GOTOOLCHAIN=go1.27.0 GOCACHE=/tmp/node-agent-go-build \
  go test -mod=readonly -p 2 \
  -exec 'sudo env GOTOOLCHAIN=go1.27.0 GOPATH=/home/linux/go GOCACHE=/tmp/node-agent-go-build' \
  -count=1 ./...
```

No Kubernetes component deployment, backend/profile integration, production
rollout, or arm64 kernel load is claimed.

## Evidence and replay

The local evidence bundle `http1009-cos121-evidence.tar.gz` includes full
verifier logs (including the decoded 5,413-line baseline trace), raw capture
events, exit statuses, kernel configuration, serial boot log, ELF files,
disassembly, OCI identities, test/build logs, initramfs and fixture disk.
The fixture disk contains the original runner, IG executable, imported gadget
archive and Python image. Inspect `fixtures/guest.sh` before replaying.

Extract the bundle, then run from the repository root with a **new** work directory:

```sh
python3 pkg/ebpf/gadgets/http/tests/local_cos121.py \
  --work-dir /var/tmp/http1009-cos121-replay \
  --initrd /path/to/extracted/cos121/initrd.cpio \
  --fixtures /path/to/extracted/cos121/fixtures.img
```

The helper downloads the pinned public payload unless `--payload` supplies a
local copy. After guest shutdown, inspect `serial.log`; expected markers are
`RESULT baseline 1`, `RESULT patched 0`, `RESULT reattach 0`, and
`VALIDATION_FINISHED`. Mount the stopped fixture disk with `loop,ro,noload` to
inspect `results/`; require the exact baseline bounds error and 42 PASS lines
in each patched stdout log. QEMU exiting zero alone does not assert success.

## Validation after updating from main

On 2026-10-16, branch `fix/1009-http-bpf-verifier-bounds` was checked against
freshly fetched upstream `main` at
`493f1011f11be74d3b46477516eaaceb02de8871`. Merge commit
`76630452` already includes that revision without unresolved conflicts.
The verifier bounds fix remains unchanged. The production HTTP source differs
from the COS-tested revision only in upstream's local socket port byte-order
correction; therefore the recorded ELF hashes identify the reviewed revision,
not a rebuild of the merged source.

The merged checkout passed the Go 1.27 agent build, HTTP race tests and HTTP vet,
Python syntax checks for both validation helpers, the COS helper's command-line smoke check,
and `git diff --check`. The full repository suite and target-kernel capture
results above belong to the earlier validation; they were not rerun after the
merge.

The local evidence archive is
`/home/linux/.cache/http1009/http1009-cos121-evidence.tar.gz`, with SHA-256
`12b526deaea2ab6197184b810c8798fb0b7cd62741fcde3e0e4ac025b3e3bdc3`.
Publish the archive and checksum alongside the maintainer reply so reviewers
can inspect the logs and replay the validation. A local archive path is not
accessible to GitHub reviewers.
