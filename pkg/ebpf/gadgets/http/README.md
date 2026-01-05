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

