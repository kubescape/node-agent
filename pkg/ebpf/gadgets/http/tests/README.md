# Plain HTTP response continuation regression tests

## Kernel verifier and live iovec capture

On a disposable Linux host with root access, Docker, Python 3 and IG `v0.48.1`:

```sh
sudo python3 pkg/ebpf/gadgets/http/tests/verifier_capture.py \
  --output-dir /var/tmp/http-verifier-regression
```

The runner builds current HTTP source under a unique local tag, loads and
attaches it with registry pulling disabled, and requires an actual HTTP event
before checking capture. It verifies byte-for-byte payloads and the 16 KiB
event / 256 KiB syscall limits through real TCP `sendmsg`, `recvmsg`, `writev`
and `readv` calls, including empty/split vectors and short receive buffers.
It retains environment information, JSON events, generated ELF files and
verbose load logs. Any load, capture or fixture failure exits nonzero; missing
privileges are not treated as a pass. It traces only the runner's PID.

To compare an already imported release artifact, add `--image IMAGE:TAG` and
use a separate output directory. Run both versions on COS 121 build
`18867.624.2`, kernel `6.6.157+`, and confirm the baseline ELF digest is
`d278a0cf36ffcd8e95dad1b97da80422ba2e9c7d92342da4b9ff1857baa1151d`.
The baseline must reject loading and the patched image must pass. A pass on
another kernel does not establish COS compatibility. Repeat the patched run
to check detach and reattachment. The runner does not deploy node-agent or
establish backend/profile integration.

## Native continuation tests

Run `go test ./pkg/ebpf/gadgets/http/tests` from the repository root. A native C
compiler (`cc`) is required; the test explicitly skips when it is unavailable.
The harness compiles the production HTTP classifier and syscall entry/exit
functions. Only kernel metadata, BPF maps, user-memory reads and ring output are
simulated. It does not load BPF or prove verifier acceptance.

The fixtures cover isolated response headers followed by eight 4 KiB body reads
through `read`, `readv`, and `recvmsg`, a 32 KiB body in one call, split
header/body vectors with a leading empty iovec, a body arriving 31 seconds after headers,
expiry after 121 seconds, idle-timeout renewal, the exact continuation byte
budget, and stale syscall arguments reaching a skipped `MSG_PEEK` receive or
an entry whose `msghdr` cannot be read. The latter cases are deterministic map
lifecycle reproductions, not evidence that those conditions occurred in a
particular production incident.

The continuation idle window is two minutes. This accommodates slow response
bodies within the downstream HTTP tap's two-minute idle window. Directions
remain bounded by the existing 16,384-entry LRU and 256 KiB byte budget. The
longer window can retain inactive directions longer and increase LRU eviction
pressure; it does not increase map capacity. Traffic beyond the byte budget,
map eviction, ring pressure and syscalls exceeding the bounded chunk emitter
remain separate capture limitations. A separate native diagnostic of the pre-chunking emitter confirmed that a
32 KiB body in one `read`, `readv`, or `recvmsg` call was clipped to 16 KiB,
whereas eight 4 KiB calls retained the complete body. Chunking is addressed
separately. These tests do not establish that all header-only production
responses are fixed.

`continuation_stats` is a diagnostic BPF PERCPU_ARRAY with four entries, `u32` keys,
and per-CPU `u64` cumulative values. Readers must sum all possible CPU slots
for each key. Updates use local increments without a shared atomic counter:

| Key | Meaning |
| --- | --- |
| 0 | No tracked direction; includes ordinary non-HTTP candidates, not proven loss |
| 1 | A body candidate found an expired direction |
| 2 | A direction reached or exceeded the byte budget; exact completion is counted even though its final bytes are forwarded |
| 3 | Recording a newly classified direction failed |

The same per-CPU layout applies to `capture_loss`; its three reason keys are
unchanged. Neither map changes the payload/event ABI, but readers of the old
shared ARRAY layout must adapt to per-CPU values. The native capture harness
checks the production map types and isolates increments on two simulated CPUs.
