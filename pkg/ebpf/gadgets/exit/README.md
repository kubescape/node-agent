### Exit Gadget

Trace `sched_process_exit` and emit events with process metadata and exit details.

### What it reports
- **timestamp_raw**: Monotonic timestamp (ns)
- **process**: PID, TID, PPID, UID, GID, command, and image data captured by Inspektor Gadget
- **exit_code**: Process exit code
- **exit_signal**: Signal that caused the exit (if any)
- **upper_layer**: Whether the executable is on overlayfs upper layer

Field descriptions live in `gadget.yaml`.

### Build
```bash
cd pkg/ebpf/gadgets/exit
sudo ig image build -t exit:latest .
```

### Run
```bash
sudo ig run exit:latest --verify-image=false
```

### Development
- eBPF program: `program.bpf.c`
- Event schema: `program.h`
- Metadata and columns: `gadget.yaml`

