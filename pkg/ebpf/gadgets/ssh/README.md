### SSH Gadget

Detect SSH connections by scanning TCP payload for "SSH-" signature and emit events with network and process metadata.

### What it reports
- **timestamp_raw**: Monotonic timestamp (ns)
- **netns_id**: Network namespace ID
- **process**: PID, TID, PPID, UID, GID, command, and image data captured by Inspektor Gadget
- **src**: Source IP and port
- **dst**: Destination IP and port

Field descriptions live in `gadget.yaml`.

### Build
```bash
cd pkg/ebpf/gadgets/ssh
sudo ig image build -t ssh:latest .
```

### Run
```bash
sudo ig run ssh:latest --verify-image=false
```

### Development
- eBPF program: `program.bpf.c`
- Event schema: `program.h`
- Metadata and columns: `gadget.yaml`
