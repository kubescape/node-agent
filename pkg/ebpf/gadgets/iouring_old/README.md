### io_uring Gadget

Trace io_uring submit events. Uses runtime kernel version detection to choose between `io_uring_submit_req` (>= 6.3) and `io_uring_submit_sqe` (< 6.3).

### What it reports
- **timestamp_raw**: Monotonic timestamp (ns)
- **process**: PID, TID, PPID, UID, GID, command, and image data captured by Inspektor Gadget
- **opcode**: io_uring opcode
- **flags**: io_uring request flags

Field descriptions live in `gadget.yaml`.

### Build
```bash
cd pkg/ebpf/gadgets/iouring_old
sudo ig image build -t iouring_old:latest .
```

### Run
```bash
sudo ig run iouring_old:latest --verify-image=false
```

### Development
- eBPF program: `program.bpf.c`
- Event schema: `program.h`
- Metadata and columns: `gadget.yaml`
