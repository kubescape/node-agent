### Symlink Gadget

Trace `symlink(2)` and `symlinkat(2)` syscalls and emit events with process metadata and the source/target paths. Useful for detecting suspicious symlink creation inside containers and host processes.

### What it reports
- **timestamp_raw**: Monotonic timestamp (ns)
- **mntns_id**: Mount namespace ID
- **process**: PID, TID, PPID, UID, GID, command, and image data captured by Inspektor Gadget
- **oldpath**: Existing path the symlink points to (target path)
- **newpath**: Path of the new symlink to be created (destination path)
- **upper_layer**: Whether the executable is on overlayfs upper layer

Field descriptions live in `gadget.yaml`.

### Build
Requires Inspektor Gadget CLI (`ig`) and Docker/Podman.

```bash
cd pkg/ebpf/gadgets/symlink
sudo ig image build -t symlink:latest .
```

### Run
```bash
sudo ig run symlink:latest --verify-image=false
```

Example output (columns may vary by UI):
```
RUNTIME.CONTAINERNAME  COMM       PID    TID    UPPER  OLDPATH                  NEWPATH
<container/name>       ln         12345  12345  true   /etc/hosts               /tmp/hosts-link
```

### Notes
- Requires eBPF and sufficient privileges (CAP_BPF/CAP_SYS_ADMIN or root).
- Mount-namespace filtering and process enrichment are handled by Inspektor Gadget helpers.
- On older kernels without ring buffer helpers, events fall back to perf output.

### Development
- eBPF program: `program.bpf.c`
- Event schema: `program.h`
- Metadata and columns: `gadget.yaml`

