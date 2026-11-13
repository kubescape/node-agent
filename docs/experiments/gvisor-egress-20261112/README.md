# gVisor egress visibility, 12 November 2026

This is the network-egress gate from
[design #23](https://github.com/kubescape/designs-and-proposals/pull/23). Before
any egress signal is built on gVisor's `syscall/connect` trace point, it asks
what one record actually means: an attempt, an established connection, or
packets leaving the sandbox. It also measures what the point misses and how
well it attributes traffic. Nothing here changes node-agent code, and the
emitted production network-event count is zero.

## Method

Each case runs a small Python workload in its own gVisor Pod (runsc `sandbox`
networking, i.e. gVisor's netstack). The research receiver records
`container/start`, `syscall/connect` enter and exit, and the raw `sendto` and
`sendmsg` exit points. The same traffic is measured on the host at three more
levels:

| Level | Source | Question it answers |
|---|---|---|
| syscall | `connect` records with the container's claimed ID | What did the sandboxed process ask for, and what did netstack return? |
| packets | `tcpdump` on the Pod bridge (`cni0`) and the uplink | Did anything leave the sandbox, and leave the node? |
| conntrack | `conntrack -E` events for the Pod IP | What did the host's connection tracking see and confirm? |
| delivery | a host TCP and UDP listener on the node IP | Did the destination accept or receive it? |

Destinations are a node listener (TCP 18080, UDP 18081), a closed node port
(18082), a TEST-NET-1 address that is routed off the node and never answers
(192.0.2.10), and cluster DNS. One case runs under a NetworkPolicy that denies
all egress.

## Result

Three full runs were kept (`run-e`, `run-f`, `run-g`). Each has 11 workload
containers and 62 retained records. All three gave the same result for every
attempt, egress and delivery question below. They differed only in TCP
teardown detail: 5 or 6 packets per connection, which closing states conntrack
reported, and whether a conntrack DESTROY event fell inside the capture window.

| Case | `connect` exit | Packets from Pod | Conntrack | Delivered |
|---|---|---|---|---|
| TCP to listener | 0 | SYN, data and teardown (5–6 packets) | ESTABLISHED, assured | yes, 1 byte |
| TCP to closed port | errno 111 (refused) | 1 SYN, RST back | NEW then DESTROY | no |
| TCP to blackhole, non-blocking | errno 115 (in progress) | 3 SYNs, all also left on the uplink | NEW SYN_SENT only | no |
| TCP denied by NetworkPolicy, non-blocking | errno 115 (in progress) | 1 SYN, ICMP port unreachable back | **none** | no |
| UDP `connect()` without sending | 0 | **none** | none | no |
| UDP `sendto()` without `connect()` | **no record** | 1 datagram | NEW udp | yes |
| UDP `connect()` then `send()` | 0 | 1 datagram | NEW udp | yes |
| DNS lookup (musl) | **no record** | 8 queries | NEW/UPDATE udp | (not measured) |
| Two Pods connecting at once | 0, one per container | as for TCP to listener | ESTABLISHED, assured | yes, both |
| TCP after the trace connection was closed | **no record** | as for TCP to listener | ESTABLISHED, assured | yes |

Every run passed these validity checks, and the analysis rejects a run that
fails any of them: zero decode/transport errors, zero local queue drops, zero
rejected trace connections, zero sender-reported (runsc) drops, all three
capture processes still running at startup and at the end of the trial and
each capture non-empty, a non-empty trace with a start claim for every trial
container, the baseline blocking TCP connects (`tcp_established` and both
concurrent Pods) recorded at enter and exit with result 0, and, for the
disconnect case, a workload confirmed RUNNING before and right after the
receiver disconnected. Without the trace and baseline checks, a run whose
trace was never captured could make missing `connect` records look like a
property of gVisor. None of this proves
complete delivery.

## What a `connect` record means

- **It is an attempt, not egress.** A record exists for every `connect()` call,
  whatever happens next. A refused, blackholed or policy-denied attempt has the
  same shape as a successful one apart from the exit code.
- **A blocking TCP connect that returns 0 is an established connection.** In
  every such case conntrack confirmed ESTABLISHED and the listener accepted.
  This is the only case where the record alone is strong evidence.
- **A non-blocking connect returns EINPROGRESS and says nothing about the
  outcome.** The blackholed and the policy-denied attempts looked identical in
  the trace (errno 115), although one sent three SYNs off the node and the
  other was rejected at the host after one SYN. The final result is only
  visible later through `poll`/`getsockopt`, which this trace configuration
  does not capture. Most network libraries connect this way.
- **A UDP `connect()` sends nothing.** It returned 0 with no packet and no
  conntrack entry.
- **A NetworkPolicy reject is invisible inside the sandbox trace.** Host
  conntrack recorded nothing for that attempt either, because the packet was
  rejected before its entry was confirmed. Only the bridge capture showed the
  SYN and the ICMP reply.

Exit results are reported in the `Exit.errorno` field with `Exit.result` 0. A
consumer has to read both fields.

## What the point misses

Egress without any `connect` record happened in three cases in every run:

- **UDP `sendto()` without `connect()`.** The datagram was delivered.
- **DNS from musl libc** (Alpine), which sends queries with `sendto()`. Eight
  queries left the Pod with no `connect` record.
- **A sandbox whose trace connection was lost.** After the receiver closed the
  connection, runsc did not reconnect, and a delivered TCP connection had no
  record at all. This is the same behavior #1091 found for stops.

The raw `sendto`/`sendmsg` points saw the first two cases, but raw syscall
points carry only numeric arguments. The destination sockaddr is a pointer,
so they cannot say where the data went.

## Attribution

Inside the trace, attribution is good: every `connect` exit record carried the
claimed container ID of the Pod that made it, including the two concurrent
Pods, and none was unattributed. The destination is the address the process
asked for. For a Service that is the ClusterIP: conntrack's original
destination for DNS was 10.43.0.10:53, while the packets on the bridge were
already addressed to the CoreDNS Pod (after DNAT). Traffic leaving the node is
masqueraded to the node IP, so beyond the node only conntrack ties it back to
the Pod.

The host's view uses the Pod IP. That identifies the sandbox, not the process
or actor inside it. Neither view gives per-actor or per-session attribution,
which stays out of scope.

## Conclusion

`syscall/connect` is a reliable record of **connection attempts and their
immediate result**, attributed to the container. It is **not** an egress
signal by itself: it reports attempts that send nothing (UDP connect) or are
blocked (policy reject), and it misses real egress (UDP `sendto`, musl DNS,
and everything after a lost trace connection). For blocking TCP only, a
result of 0 matched an established, delivered connection in every case.

A defensible future signal would be "connection attempt" with the exit code,
never "egress". Proving that data left the sandbox needs a host-side source
such as conntrack or flow capture keyed by Pod IP. No implementation is
proposed here, and a production network event would need maintainer
agreement on that wording first.

## Coverage and environment

All runs used one self-managed ARM64 Ubuntu VM (kernel 6.8.0-147-generic,
K3s v1.37.1+k3s1 with its embedded NetworkPolicy controller), runsc
release-20261019.0 with systrap and `sandbox` networking, conntrack 1.4.8 and
tcpdump 4.99.4. Details are in [environment.json](evidence/environment.json).
Earlier runs were not retained. An exploratory first run captured no ICMP and
mis-parsed DNS lines. Three later runs gave the same per-case results as the
kept ones, but they were made before the validity checks and export scoping
above existed, so they were replaced by runs made with the final scripts.

Not covered: IPv6, TCP Fast Open, `sendmsg` with a destination address,
host-network (`--network=host`) sandboxes, glibc resolvers, long-lived or
high-rate connections, more than two concurrent Pods, x86_64, managed GKE and
any overhead measurement. The `conntrack` package was installed on the test VM
for this experiment.

## Privacy and bounds

The receiver accepts only message types 1, 6 and 10, and from type 6 only
syscall numbers 206 and 211. It keeps numeric context, claimed IDs, connect
results and the family, address and port of AF_INET and AF_INET6 destinations.
It discards argv, cwd, env, credentials, process names and fd paths, never
keeps AF_UNIX paths, caps sockaddr size, and clears raw buffers after parsing.
Only trace records from the trial's own sandboxes are exported: a trace
connection counts only if it carried a start claim for a container or sandbox
in the trial ledger, and every kept record that names a container must name a
ledger one (none had to be excluded in the kept runs). Raw tcpdump and
conntrack text stayed in a root-only directory on the VM. Only sanitized rows
(timestamps, 5-tuples, TCP flags, ICMP type, conntrack original and reply
tuples and state) were exported. Bridge packets and conntrack rows are kept
only for the trial's Pod IPs. Uplink packets are kept only when they match the
NAT'd reply tuple of a trial conntrack flow, because after masquerading they
carry the node address instead of the Pod IP. Other Pods on the node share the
capture range and were dropped. The raw files were deleted afterwards. A canary in every
workload's argv is absent from the evidence, and so is the DNS query name. All
addresses are lab addresses on the test VM. This is a disposable research
tool. Do not run it as a node-agent source or expose its socket to Pods.

## Reproduce on a disposable node

1. Save the runsc runtime configuration privately and point `pod-init-config`
   at [pod-init.json](pod-init.json), so new sandboxes use an experiment-owned
   `Default` session. Make sure `/run/kubescape` is a root-owned 0700
   directory. Install `tcpdump` and `conntrack`.
2. As root on the node, with a RuntimeClass `gvisor` mapped to handler `runsc`:

   ```sh
   python3 trial.py --namespace gvisor-egress-20261112-x --output OUT \
     --private /root/PRIVATE --node-ip NODE_IP --uplink UPLINK_IFACE
   python3 analyze.py reduce /root/PRIVATE OUT
   python3 analyze.py summarize OUT --node-ip NODE_IP
   ```

   The trial creates its own namespace and a deny-all egress NetworkPolicy that
   selects only the policy case's Pod.
3. Delete the namespace and `/root/PRIVATE`, restore the runtime configuration
   and remove `/run/kubescape/gvisor-egress`.

Unit tests (decoder, sockaddr privacy, retained evidence and negative cases):

```sh
python3 -m unittest discover -s docs/experiments/gvisor-egress-20261112 -p 'test_*.py'
```

Artifact hashes are in [evidence-sha256.json](evidence-sha256.json).
