# Network event attribution by connection 4-tuple

Network events (`network` gadget, `pkg/ebpf/gadgets/network`) name the process that opened a
connection. For outgoing TCP connections that process is now looked up by the connection's full
4-tuple instead of its local port alone.

## The problem (SUB-9610)

The gadget is a packet socket filter. It used to find the process through the inspektor-gadget
socket enricher map, keyed `{netns, family, proto, local port}`. That map keeps the first socket
on a key.

Linux allows several live TCP connections on one local port as long as their remote endpoints
differ. A host-network pod shares the node's netns. So when a host process (or the kernel) gets
the local port that a pod process already uses, its SYN is found under the pod process's entry. It
was reported as the pod's connection. In one week of prod data, R1117 (Outbound SMB Connection)
blamed 39 SMB connections on MetalLB `speaker`, FRR `bgpd`, the pushprox client, CSI sidecars,
`node_exporter` and `kepler`. These connections could also be learned into those pods' network
profiles.

## Behaviour

| Packet | Process looked up by |
|---|---|
| Outgoing TCP SYN | Full 4-tuple: netns, local and remote address, local and remote port. Filled by `kprobe/tcp_connect` as the connection is made. |
| Outgoing TCP SYN with no 4-tuple entry (connection made before the gadget started, or LRU eviction) | Port-keyed socket enricher map, as before |
| Incoming TCP SYN, UDP | Port-keyed socket enricher map, as before |

When the 4-tuple names a host task:

- **Container filter on (the normal Kubernetes case):** the event is dropped.
- **Host monitoring:** the event reports the host task.

When the 4-tuple names a different container's task, the event reports that task.

`proc` and `exepath` come from the task that sends the SYN, normally the one that called
`connect()`. A deferred TCP Fast Open connection (`TCP_FASTOPEN_CONNECT`) sends its SYN from the
first `write()` or `sendmsg()`, so the task that makes that call is reported. For a kernel
connection (the in-kernel CIFS client, NFS, ceph, iSCSI, extra MPTCP subflows) that task is a kernel
thread or kworker, with an empty `exepath`. The container filter drops these.

IPv6 sockets connecting to IPv4-mapped addresses are keyed as IPv4, because their packets are IPv4.

## Limits

These cases still use the port-keyed lookup, so the misattribution can still happen for them:

- **NAT.** The kprobe records the tuple before netfilter, and the packet socket sees the SYN after
  it. A SYN whose destination or source was rewritten never matches. Examples: kube-proxy
  iptables/IPVS DNAT to a ClusterIP, SNAT/masquerade, IPv4 source routing. Cilium socket
  load-balancing rewrites at connect time, so it does match.
- **SYNs after an eviction.** Every TCP connect on the node fills the map. On a busy or many-CPU
  node, a retransmit sent 1 or 3 seconds later can find its entry evicted. The first SYN usually
  reaches the filter right after its entry is inserted, but a queueing discipline can hold it long
  enough for the entry to be evicted too.
- **SYNs that do not come from `tcp_connect()`.** These come from raw sockets or `TCP_REPAIR`. If
  one reuses a recorded 4-tuple, it is attributed to that tuple's last `connect()` caller. Entries
  are not deleted.

## Cost

- One extra kprobe on `tcp_connect`. The socket enricher already probes the same function.
  - Each TCP connect on the node now also walks the executable path (`get_path_str`) and does one
    LRU update. The enricher already does the same work on that connect.
- Memory:
  - The 4-tuple map is an LRU hash with 8192 preallocated entries: about 3.4 MB (key, value and
    element header).
  - `gadget/filesystem.h` adds its per-CPU path buffer: 32 KiB per CPU, for example 4 MiB on
    128 CPUs.
- One extra map lookup per outgoing SYN.

## Verification

- `go test ./pkg/ebpf/gadgets/network/...`: the native packet harness covers the key layout, the
  owner overriding the socket entry in both filter directions, ingress/UDP fallback, and path
  truncation.
- Live reproduction with `ig`, run for IPv4, IPv6 and IPv4-mapped addresses:
  1. A process in a `--network host` container held local port P.
  2. A host process connected from the same port P to another destination.
  - Before the fix, the host connection was reported with the container process's pid, mount
    namespace and path.
  - After the fix, it is dropped under a container filter, and reported as the host process with
    `--host`.
