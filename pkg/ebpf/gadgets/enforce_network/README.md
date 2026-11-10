# enforce_network

Container egress enforcement with BPF LSM programs. It enforces an egress
network policy: destination CIDRs (IPv4 and IPv6), destination ports and port ranges,
and protocol (TCP, UDP or any), for `connect` and for every send with a
destination address (`sendto`, `sendmsg`, `sendmmsg`, TCP Fast Open, io_uring).

The gadget is built on the [common enforcement library](../common/README.md).
It depends only on Inspektor Gadget and that library. One instance runs per
node, with the same model as enforce_privilege:

- A **slot** is one combination of policy documents; containers with the same
  combination share it. Binding or unbinding a container is a live write to the
  `bindings` map. Limits per node: 1024 containers, 64 slots, 32 documents per
  slot, 16384 prefixes and 1024 distinct rule lists.
- The policy maps are frozen per instance. A new or edited policy needs a new
  instance (the owner starts it, binds every container, then stops the old one).

`policy/` parses and compiles policy documents; `runtime/` is the native
operator an owner drives with `runtime.WithConfig` and `runtime.GetBindings`.

Requires cgroup v2, kernel BTF and BPF LSM enabled (`bpf` in
`/sys/kernel/security/lsm`). A node without BPF LSM cannot run it. Build the
image with `make build` (it sets `IG_SOURCE_PATH`, see the library README).

## Programs

The gadget attaches `lsm/socket_connect` and `lsm/socket_sendmsg`. They share
the maps and the decision function (`net_decide` in `network_policy.h`). Each
program returns the verdict of an earlier BPF LSM program when it is not 0, so
it never replaces another deny (`runtime/lsm_chain_kernel_test.go`).

## Policy

A policy document (YAML or JSON), parsed with `policy.Parse`. Full example:
[examples/policy.yaml](examples/policy.yaml).

```yaml
version: 1
name: example                # qualifies rule names in events
policy:
  mode: enforce              # audit | enforce | off
  egress:
    default: allow           # allow | deny
    defaultMode: enforce     # optional; else the policy mode
    rules:
      - name: no-test-net-1
        action: deny
        cidrs: [192.0.2.0/24, "2001:db8::/32"]
        except: [192.0.2.7/32]
      - name: no-dns-to-test-net-3
        action: deny
        proto: udp           # tcp | udp | any (default)
        cidrs: [203.0.113.0/24]
        ports: [{from: 53}, {from: 5300, to: 5399}]
```

- A rule has a name, an action (`allow` or `deny`), an optional mode, an
  optional origin (copied to events), one or more CIDRs, optional port ranges
  (none = every port) and a protocol. The egress section can set
  `defaultMode` and `defaultOrigin` for its default. A missing origin and an
  explicit `""` are different: only a present origin is reported.
- Resolution: an explicit deny beats an allow, an allow beats the default,
  independent of rule order. Each rule has its own mode.
- `except` (deny rules only) lifts that deny for prefixes inside its CIDRs. The
  other rules and the default still apply there.
- An IPv4 rule also matches IPv4-mapped IPv6 destinations (`::ffff:a.b.c.d`).
  An IPv6 rule never matches them, so `::/0` covers IPv6 only. IPv4-mapped
  CIDRs are rejected; write them as IPv4.
- `tcp` also matches MPTCP and `udp` also matches UDP-Lite. Other protocols
  (for example ICMP ping sockets) match only `any` rules and the default.
- **Several documents in one slot** combine by the shared
  [merge contract](../common/merge/CONTRACT.md): the union of rules; the
  default is deny if any document denies, with the strictest mode among the
  documents that agree; an audit deny never weakens another document's enforce
  default deny; an explicit allow still beats another document's default deny.

## How it decides

- **Scope.** Every task in a bound cgroup is judged; there is no arming.
  Container runtimes make no inet connect and no addressed send inside the
  container cgroup before the workload runs, so `docker run` and `docker exec`
  keep working under a default deny. A binding covers its exact cgroup; a
  subtree binding (the pod cgroup binding, `BINDING_SUBTREE`) also covers its
  descendant cgroups. A task in a child cgroup of a Strict exact binding is a
  structural fault (see below).
- **Structural faults.** A bound cgroup whose slot has no policy (generation
  0), or a task outside a Strict exact binding's scope, is not treated as
  unbound. A Strict binding (its slot's mode is enforce, `BINDING_STRICT`)
  denies with `-EPERM` and counts a slot fault in `net_faults`; an Audit
  binding allows. Both count in `counters` slot 4. The owner reads `net_faults`
  with `Bindings.SlotFaults`, and a nonzero count makes the binding's
  protection unconfirmed.
- **Hooks.** `connect` and every send with an address, on AF_INET and
  AF_INET6 sockets. A send without an address (a connected socket) is not
  judged; its destination was judged at `connect`. A connected UDP socket that
  sends to another address is judged at that send. A TCP or MPTCP send with an
  address is judged when it sets `MSG_FASTOPEN` or the socket is closed (TCP
  Fast Open connects there); otherwise TCP ignores the address. A
  `MSG_FASTOPEN` send is judged on any socket state, because the state can
  change after the hook reads it. So on a connected socket a `MSG_FASTOPEN`
  send to a denied address fails with `EPERM` (the kernel alone returns
  `EISCONN`). The io_uring sends, `SEND_ZC` and `SENDMSG_ZC` included, pass
  through the same hook with their flags.
- **Address.** Parsed by the address family, not the socket family:
  an AF_INET6 UDP socket accepts a `sockaddr_in`, and an AF_INET socket sends
  to a `sockaddr_in` whose family is AF_UNSPEC. An AF_INET6 raw or L2TP/IP
  socket sends to a `sockaddr_in6` whose family is AF_UNSPEC (the kernel reads
  it as AF_INET6); other AF_INET6 sends with AF_UNSPEC use the peer and are
  not judged. `connect` with AF_UNSPEC (disconnect) is not judged. An address that is not IPv4 or IPv6 gets the
  default.
- **Deny** fails the connect or send with `EPERM` before it happens. Audit
  allows and reports.
- The decision (`network_policy.h`) takes only a slot, a destination and a
  protocol, so other hook types can share the maps.

## Known limits

- Host names, DNS, TLS and HTTP are not judged; the policy is CIDRs only.
- Unix and packet sockets and `bind`/`listen` are not judged.
- A task is judged by its cgroup at the time of the call.
- A socket that connected before its container was bound, or before a deny
  applied to it, keeps sending: a send without an address is not judged. A
  controller can prepare the slot in advance and bind a new container as soon
  as its cgroup exists. A live change to a stricter policy does not cut
  existing connections.
- SCTP is not covered. `SCTP_SOCKOPT_CONNECTX` goes through `security_sctp_bind_connect`, which has no program here.
- MPTCP extra subflows that the kernel path manager opens are not judged;
  only the connect of the MPTCP socket is.
- A bound cgroup covers its child cgroups to a depth of 31 levels only.
  Deeper cgroups are not judged.
- A raw socket with `IP_HDRINCL` writes its own IP header, so the address of
  the send is not the destination. Block raw sockets with the privilege
  section (drop the `NET_RAW` capability).

## Using it outside this repository

The same as enforce_privilege: a Go program drives it with
`runtime.WithConfig` and `runtime.GetBindings` (see
`runtime/runtime_kernel_test.go`, which loads the example file). There is no
`ig` command for it yet. The guard test in
`common/enforcement/portability_test.go` covers this folder.

## Maps and events

| Map | Content |
|---|---|
| `net_slots` | array, slot → merged default `{rank, rule_id, origin_id, mode, generation}` and the documents whose default denies in enforce mode |
| `net_prefix` | LPM trie, `{prefixlen, slot, 16-byte address}` → rule list index; IPv4 stored IPv4-mapped; each entry lists every rule that covers the prefix |
| `net_rules` | array, rule list index → up to 32 `{port range, protocol, rank, document, rule_id, origin_id}` |
| `bindings`, `counters` | from the common library |

The `verdict` datasource shares `generation`, `cgroup`, `deny` and `mode` with
the other enforcement gadgets and adds `host_pid`, `rule_id`, `origin_id`,
`is_default`, `slot`, `comm`, `hook` (the program that judged) and `dst` (address, port, protocol;
IPv4-mapped addresses as IPv4). Only denies are reported (mode 1 = audit, the
connection was allowed). Rule and origin names are in the owner's compiled
policy (`RuleNames`, `Origins`). Origin id 0 means no origin; an explicit empty
origin has its own id. A default verdict (rule `default`) takes its origins from
`DefaultOrigins[slot]`: the `defaultOrigin` of the documents that agree with the
slot's merged default. Reporting is limited to 100 events per CPU per
second; enforcement is never throttled.
