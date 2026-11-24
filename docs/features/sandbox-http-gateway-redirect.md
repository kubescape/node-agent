# Sandbox policy http section: gateway redirect

The `http` section of a `SandboxPolicy` is enforced by a gateway that runs on
each node. node-agent's part is to send a bound pod's TLS connections to AI
addresses into that gateway and to record, in the kernel, which pod owns each
connection. The code is in `pkg/sandboxpolicy/httpgateway`.

This page describes what is merged. The service does not start the redirect
yet; the plan for the remaining steps is
`docs/plans/2026-11-24-sandbox-http-gateway-redirect.md`.

## What the programs do

The package loads its eBPF programs with `cilium/ebpf` and attaches them once,
at the cgroup root. They are not Inspektor Gadget gadgets, because the gadget
runtime attaches no cgroup socket-address, sockops or iterator programs.

A task is covered when its own cgroup has an entry in the `bindings` map, or
else when a cgroup above it has one (the nearest one wins). For a covered task:

- A TCP connection to port 443 whose destination is in the binding's `ai_dsts`
  set is rewritten to the gateway listener (`cgroup/connect4`, and
  `cgroup/connect6` for an IPv4-mapped destination on a dual-stack socket).
- Once the connection is established, a sockops program writes its entry to
  `conns`, keyed by the socket's own address and port. The entry holds the
  bound cgroup, the pid, the binding id and the original destination. It is
  deleted when the socket closes.
- A connection made straight to the gateway listener is recorded the same way,
  with no rewrite.
- UDP to port 443 and real IPv6 to port 443 are refused with EPERM when the
  destination is in the same set, so the client falls back to TCP over IPv4.

Everything else keeps its own route: another port, a destination outside the
set, an entry that has expired, a destination in `exempt`, a task that is not
covered, and a binding whose gate is failing open. In that last case the UDP
and IPv6 refusals lift too.

A BPF LSM `socket_connect` program, such as the one the `network` section
uses, runs before the rewrite. It sees the destination the pod asked for, and
when it denies, the redirect never runs.

## Which pods are bound

`Decide` applies the rule to one pod. A pod is bound when all of these hold:

- a policy with an `http` section selects it, and that policy's `spec.mode` is
  not `off`;
- the pod has the annotation `sandbox.kubescape.io/gateway-prepared`, which the
  gateway's admission webhook sets when it injects the trust bundle;
- the annotation holds the fingerprint of the root CA that this node's gateway
  chains to.

The binding's posture is `deny` when any covering policy has
`onUnavailable: deny`, and `allow` otherwise.

During a root rotation the operator publishes the state in the ConfigMap
`sandbox-gateway-trust` (key `rotation.json`). Inside the rotation window a pod
that trusts the current root stays bound. Once the window has ended, or at once
under an emergency rotation, a pod whose annotation lacks the next root is
unbound: its connections go direct until it restarts and is prepared again.
Such a pod, and a pod with no annotation or with another root, is reported as
needing a restart.

`Reconciler.Apply` takes the pods that policies select and makes the `bindings`
map match. Each bound pod gets one binding id, written for its pod cgroup and
for every container cgroup. The id stays the same while the pod lives, and a
new id is never one that a connection, an AI set entry or a binding left by an
earlier process still carries. When a binding goes, its `ai_dsts` entries go
with it. Until the DNS feed exists, a static list of addresses from
configuration is written to every binding's set.

The reconciler never changes the gate value of an entry it rewrites; that
value belongs to the health gate. A `deny` binding's gate is always
redirecting.

`ExemptSet` builds the `exempt` map's content: the cluster's pod and service
ranges, the node's own addresses, and extra ranges from configuration.

## Health gate

The redirect must not make a pod's AI calls depend on a gateway that is down,
unless the policy asks for that. `HealthGate` probes the gateway's health
listener and turns the answer into the gate value of each binding.

It probes three paths, each answered by a different process:
`/healthz/envoy`, `/healthz/processor` and `/healthz/certs`. The last one
returns `canDecrypt`, `decryptValidUntil` and `rootFingerprint`. The defaults
are a round every 500 ms with a 400 ms timeout.

The gate opens on the first round in which Envoy or the processor does not
answer, `canDecrypt` is false, or the last known `decryptValidUntil` is less
than five minutes away. A certificate probe that does not answer opens nothing
by itself: the last answer stands, and the node controller is reported as
degraded. Before the first answer there is no certificate signal.

What open means depends on the pod's posture. Bindings with posture `allow`
get gate value 1: their new connections keep their own route, and the UDP and
IPv6 refusals lift. Bindings with posture `deny` keep gate value 0: their
connections still go to the gateway and fail there.

The gate closes in steps, once every signal has been healthy for 10 seconds:

1. The bindings that failed open get gate value 2. New connections go to the
   gateway again.
2. The socket kill runs for each pod that failed open, so the direct
   connections it opened during the window are reset.
3. The bindings get gate value 0, and only then does `Status` report the node
   as redirecting.

A failure during these steps opens the window again. A kill that fails keeps
the node at step 2, and the next healthy round tries again. A gateway that
flaps for less than 10 seconds at a time resets nothing.

A pod bound while the window is open follows its posture at once, and is
killed with the others at recovery. A pod bound at any other time is killed
right after the bind (`Bound`).

After a restart the gate reads the gate values the last process left. A window
that was open or half closed is still open, and its recovery still runs the
kill. While node-agent is down nothing moves the gate.

The kill cannot run on a kernel before 6.5, for a pod on the host network (the
iterator walks a whole network namespace, which that pod shares with every
other host-network workload), or for a pod whose network namespace is not
known. Each such case is counted per pod (`PreAttachBypass` in `Status`): the
pod may still hold direct connections to AI addresses.

## Socket kill

A connection that a pod opened before it was bound is not redirected, and can
carry requests for hours. `KillDirect` closes such connections with a
`bpf_sock_destroy` socket iterator: TCP connections to port 443 of an address
in the binding's set that have no `conns` entry. The application reconnects
and the new connection is redirected.

The iterator walks the network namespace of the thread that runs it. It needs
Linux 6.5. On an older kernel `KillDirect` returns `ErrKillUnsupported` and the
redirect itself still works.

## Pinned maps

Maps and links are pinned under one bpffs directory
(`kubescape-sandbox/http` on the host bpffs), so the redirect keeps running
while node-agent is down: connections still go to the gateway and `conns`
keeps filling. On the next start the loader reopens the maps with their
content and swaps its programs into the links that are already attached.
`Remove` detaches everything and deletes the pins.

Other components read four of the maps. Their layout is a contract; the
constants and codecs are in `layout.go`, and `layout_test.go` fails when the
compiled object and the constants disagree.

| Map | Key | Value |
|---|---|---|
| `bindings` | cgroup id, u64 (8 bytes) | binding id u32, posture u8 (0 allow, 1 deny), gate u8 (0 redirecting, 1 failing open, 2 recovering), padded to 8 bytes |
| `ai_dsts` | binding id u32, address 16 bytes (20 bytes) | expiry u64, on the clock of `bpf_ktime_get_ns`; 0 never expires |
| `conns` | the pod socket's address 16 bytes, port u16 (18 bytes) | cgroup id u64, pid u32, binding id u32, original destination address 16 bytes and port u16, padded to 40 bytes |
| `exempt` | LPM trie: prefix length u32, address 16 bytes (20 bytes) | u8 |

Integers are in host byte order, ports included. Addresses are in network
order, IPv4 in its IPv6-mapped form (`::ffff:a.b.c.d`); an IPv4 prefix in
`exempt` is stored 96 bits longer. `conns.cgroup` is the cgroup whose binding
matched, so it is always a key of `bindings`. `conns.pid` is the thread group
id as the initial pid namespace sees it. `conns` is an LRU hash.

The directory also holds the loader's own maps (`pending`, `cfg`, `stats`) and
one `link_<program>` pin per attachment. They are not part of the contract.

## Building the eBPF objects

The compiled objects and their Go bindings are committed
(`redirect_bpfel.*`, `sockkill_bpfel.*`, `testdata/lsmprobe.bpfel.o`), so
building node-agent needs no clang. After changing a `.bpf.c` file, rebuild
them and commit the result:

```
make httpgateway-bpf
```

## Tests

`go test ./pkg/sandboxpolicy/httpgateway/` runs the layout tests anywhere. The
kernel tests need root, cgroup v2 at `/sys/fs/cgroup`, a bpffs at
`/sys/fs/bpf` and the initial pid namespace, and are skipped otherwise. They
create their own cgroups and loopback listeners and bind only those, so
nothing else on the machine is redirected. The hook-order test also needs BPF
LSM to be active, and the kill test needs Linux 6.5.
