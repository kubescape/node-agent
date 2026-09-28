### HTTP Monitor Gadget

Monitor HTTP traffic at the system level using eBPF to capture HTTP requests and responses, providing real-time visibility into web application communications for security analysis and monitoring.

### What it reports
- **timestamp_raw**: Monotonic timestamp (ns)
- **proc**: PID, TID, PPID, UID, GID, command, and image data captured by Inspektor Gadget
- **type**: HTTP event type (2=request, 3=response)
- **buf**: HTTP request or response payload data captured from the network socket
- **sock_fd**: Socket file descriptor number used for the HTTP communication
- **socket_inode**: Inode number of the socket, used to uniquely identify sockets across processes
- **syscall**: Name of the system call that triggered the HTTP event capture (e.g., read, recv, send)

Field descriptions live in `gadget.yaml`.

### Build
```bash
cd pkg/ebpf/gadgets/http
sudo ig image build -t http:latest .
```

### Run
```bash
sudo ig run http:latest --verify-image=false
```

Example output (columns may vary by UI):
```
RUNTIME.CONTAINERNAME  COMM       PID    TID    TYPE  SOCK_FD  SYSCALL
<container/name>       curl       12345  12345  2     4         send
<container/name>       nginx      12346  12346  3     4         send
```

### Notes
- Requires eBPF and sufficient privileges (CAP_BPF/CAP_SYS_ADMIN or root).
- Monitors HTTP traffic by intercepting system calls (read, recv, send, etc.) and analyzing payload content.
- Detects HTTP requests by looking for HTTP method signatures (GET, POST, HEAD, PUT, DELETE, OPTIONS, TRACE, CONNECT).
- Detects HTTP responses by looking for "HTTP" signature at the beginning of the payload.
- Uses socket inode tracking to correlate requests and responses across different processes.
- Mount-namespace filtering and process enrichment are handled by Inspektor Gadget helpers.
- On older kernels without ring buffer helpers, events fall back to perf output.

### Development
- eBPF program: `program.bpf.c`
- Event schema: `program.h`
- Metadata and columns: `gadget.yaml`


### Capture bounds and loss

A successful scalar syscall is split into at most 16 events of 16 KiB (256 KiB
per syscall). Vectored syscalls examine at most 28 descriptors and emit at most
256 KiB in total; this byte budget is shared across all vectors. At most 44
bounded steps cover descriptors and additional chunks, preserving all 28 small
vectors. Metadata is collected once per syscall in bounded per-CPU scratch
storage. Partial syscall
returns capture only bytes actually transferred. Continuation accounting uses
those transferred bytes once, independently of chunking.

Reservation failures, user-memory copy failures and work-limit exhaustion stop
capture for that syscall and invalidate its direction's continuation entry.
Later body-only data is suppressed until another HTTP start is recognized. The
`capture_loss` array contains cumulative counts of failed known-HTTP captures:
index 0 is work-limit exhaustion, 1 is reservation failure, 2 is user-memory read
failure. These are capture failures, not counts of lost bytes or HTTP messages.

The existing event ABI has no cumulative offsets or explicit loss marker. This
change prevents subsequent chunks in a failed syscall from bridging a hole, but
cannot guarantee detection of every loss in userspace or safe recovery across
concurrent syscalls on one socket. It does not turn the stream into a lossless
capture transport.

### Native regression tests

`go test -count=1 ./pkg/ebpf/gadgets/http/capture` compiles the actual production
C probes with native kernel-helper substitutes. A C compiler is required; the
test skips explicitly if none is installed. Use `-count=1`, since Go's test
cache does not track the separately compiled C source. Tests cover scalar and
vectored reads/writes at 10 KiB, 16 KiB boundaries, 20.5 KiB and 40 KiB, partial
returns, shared work bounds, and injected reservation/copy failures. These tests
complement rather than replace architecture-specific BPF verifier loads.
