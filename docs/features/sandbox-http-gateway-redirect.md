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
