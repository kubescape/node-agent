### Fork Gadget

Trace `sched_process_fork` and emit events with parent/child identifiers and process metadata.

### What it reports
- **timestamp_raw**: Monotonic timestamp (ns)
- **process**: PID, TID, PPID, UID, GID, command, and image data captured by Inspektor Gadget
- **parent_pid**: Parent process ID
- **child_pid**: New child process ID
- **child_tid**: New child thread ID

Field descriptions live in `gadget.yaml`.

### Build
```bash
cd pkg/ebpf/gadgets/fork
sudo ig image build -t fork:latest .
```

### Run
```bash
sudo ig run fork:latest --verify-image=false
```

### Development
- eBPF program: `program.bpf.c`
- Event schema: `program.h`
- Metadata and columns: `gadget.yaml`

