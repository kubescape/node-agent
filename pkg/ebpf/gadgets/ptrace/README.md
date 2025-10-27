### Ptrace Gadget

Trace `ptrace(2)` syscalls that modify target memory or registers (`PTRACE_SETREGS`, `PTRACE_POKETEXT`, `PTRACE_POKEDATA`).

### What it reports
- **timestamp_raw**: Monotonic timestamp (ns)
- **process**: PID, TID, PPID, UID, GID, command, and image data captured by Inspektor Gadget
- **request**: Ptrace request value
- **exepath**: Executable path of the calling process

Field descriptions live in `gadget.yaml`.

### Build
```bash
cd pkg/ebpf/gadgets/ptrace
sudo ig image build -t ptrace:latest .
```

### Run
```bash
sudo ig run ptrace:latest --verify-image=false
```

### Development
- eBPF program: `program.bpf.c`
- Event schema: `program.h`
- Metadata and columns: `gadget.yaml`

