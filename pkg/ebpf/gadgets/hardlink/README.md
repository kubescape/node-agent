### Hardlink Gadget

Trace `link(2)` and `linkat(2)` syscalls and emit events with process metadata and the source/target paths. Useful for auditing hard link creation inside containers and host processes.

### What it reports
- **timestamp_raw**: Monotonic timestamp (ns)
- **mntns_id**: Mount namespace ID
- **process**: PID, TID, PPID, UID, GID, command, and image data captured by Inspektor Gadget
- **oldpath**: Existing path the hard link points to (target path)
- **newpath**: Path of the new hard link to be created (destination path)
- **upper_layer**: Whether the executable is on overlayfs upper layer

Field descriptions live in `gadget.yaml`.

### Build
```bash
cd pkg/ebpf/gadgets/hardlink
sudo ig image build -t hardlink:latest .
```

### Run
```bash
sudo ig run hardlink:latest --verify-image=false
```

Example output:
```
RUNTIME.CONTAINERNAME  COMM       PID    TID    UPPER  OLDPATH                  NEWPATH
<container/name>       ln         12345  12345  true   /etc/hosts               /tmp/hosts-hardlink
```

### Development
- eBPF program: `program.bpf.c`
- Event schema: `program.h`
- Metadata and columns: `gadget.yaml`

