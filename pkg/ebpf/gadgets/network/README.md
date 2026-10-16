### Network Gadget

Trace network connection attempts (TCP and UDP) at the socket level and emit events with process metadata, source/destination addresses, ports, and protocol information. Useful for container and host-level troubleshooting, visibility, and incident response.

### What it reports

- **timestamp_raw**: Monotonic timestamp (ns)
- **netns_id**: Network namespace ID
- **endpoint**: Contains source or destination address, port, protocol, and version (see below)
  - **addr_raw.v4**: IPv4 address (network byte order)
  - **port**: TCP or UDP port (host byte order)
  - **proto_raw**: Protocol number (e.g. `6` for TCP, `17` for UDP)
  - **version**: IP version (4 or 6)
- **proc**: Process metadata (PID, TID, comm, etc.; see [types.h](../../types.h))
- **exepath**: Socket-opening executable path, empty when attribution is unavailable. C-string capped at 256 bytes (255 path bytes plus NUL); longer paths are truncated.
- **egress**: Boolean flag; true if the packet is outgoing, false for ingress

Field descriptions are defined in `program.h` and `gadget.yaml`.

### Build

Requires Inspektor Gadget CLI (`ig`) and Docker/Podman.

```bash
cd pkg/ebpf/gadgets/network
sudo ig image build -t network:latest .
```

To build with updated gadget metadata:

```bash
sudo ig image build -t network:latest . --update-metadata
```

### Run

```bash
sudo ig run network:latest --verify-image=false
```

Example output (for JSON pretty mode):

```json
[
  {
    "timestamp_raw": 1710499461023456789,
    "netns_id": 4026531993,
    "endpoint": {
      "addr_raw": {
        "v4": "0xC0A80101"
      },
      "port": 80,
      "proto_raw": 6,
      "version": 4
    },
    "proc": {
      "pid": 1532,
      "tid": 1532,
      "uid": 0,
      "gid": 0,
      "comm": "curl"
    },
    "exepath": "/usr/bin/curl",
    "egress": true
  }
]
```

Columns may vary depending on UI (see gadget.yaml for details).

### Notes

- IPv4 and IPv6 TCP SYN packets without ACK, and UDP packets to destination ports below 1024, are reported.
- Processes and namespaces are enriched at capture-time using Inspektor Gadget helpers.
- Requires eBPF and sufficient privileges (e.g. CAP_BPF/CAP_SYS_ADMIN or root).
- IPv6 extension headers are not traversed.
- The program is built for use in containers and on host OS. Filtering, enrichment, and image metadata are handled by Inspektor Gadget.
- Events are delivered via perf event arrays (compatible with all kernels).

### Path consumers

CEL `event.exepath` and network exporters read this socket metadata directly. Guard path-dependent rules with `event.exepath != ''`. This is the socket-opening process identity; inherited sockets can differ from the process sending a later packet.

For alerts, the network adapter supplies this path only as a fallback when the enriched process-tree lookup misses (`ProcessTree.PID == 0`). A populated process tree retains precedence, including its own path.

### Development

- eBPF program: `program.bpf.c`
- Event schema: `program.h`
- Metadata and columns: `gadget.yaml`
- Build/run scripts: `Makefile`

