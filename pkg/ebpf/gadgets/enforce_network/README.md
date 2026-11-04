# enforce_network

Container egress enforcement with BPF LSM or cgroup sock_addr programs. It
enforces an egress network
policy: destination CIDRs (IPv4 and IPv6), destination ports and port ranges,
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

Requires cgroup v2 and kernel BTF; the LSM tier also needs BPF LSM enabled
(`bpf` in `/sys/kernel/security/lsm`). Build the image with `make build` (it
sets `IG_SOURCE_PATH`, see the library README).

## Program tiers

The gadget has two sets of programs. They share the maps and the decision
function (`net_decide` in `network_policy.h`); only one set is used.

| Tier | Programs | Needs |
|---|---|---|
| `lsm` (default) | `lsm/socket_connect`, `lsm/socket_sendmsg` | BPF LSM active on the node |
| `cgroup` | `cgroup/connect4`, `cgroup/connect6`, `cgroup/sendmsg4`, `cgroup/sendmsg6`, attached at the cgroup v2 root | an Inspektor Gadget that attaches cgroup sock_addr programs |

- Select the tier with the gadget parameter `tier` (key `custom.tier`,
  `runtime.TierParam`): `lsm` or `cgroup`. `gadget.yaml` disables the other
  tier's programs with `attach_to: gadget_program_disabled`.
- An Inspektor Gadget that skips disabled programs at load (the kubescape
  fork change "do not load disabled programs") loads and attaches only the
  selected set. So the cgroup tier runs on a kernel without
  `CONFIG_BPF_LSM`, and the unused set costs nothing. The version in `go.mod`
  does not skip them yet: it loads both sets (the verifier checks both) and
  attaches only the selected set.
- The default stays `lsm` until the Inspektor Gadget version in `go.mod` can
  attach cgroup programs. With a version that cannot, `tier=cgroup` fails at
  start with `unsupported program ... of type "CGroupSockAddr"`.
- The native operator refuses a configuration that attaches both tiers, part
  of a tier, or no tier.
- The results are the same for the cases in `runtime/runtime_kernel_test.go`.
  Differences between the tiers:
  - The cgroup tier runs only for tasks in some cgroup with a program, so it
    costs nothing outside the bound cgroups' lookups; the LSM tier runs for
    every task on the node.
  - The cgroup tier sees the address after earlier cgroup programs (for
    example a socket load balancer that rewrites a service address to a
    backend address); the LSM tier sees the address the application asked
    for.
  - The cgroup programs do not run for raw sockets, nor for an ICMP ping
    send without `connect`. The LSM hooks run for every inet socket; those
    calls get the `any` rules and the default there.
  - The cgroup programs return 0 (the kernel returns EPERM) or 1. All cgroup
    programs on the path run, and any deny wins.

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
  (none = every port) and a protocol.
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
  keep working under a default deny. A bound cgroup also covers up to 31 levels
  of child cgroups.
- **Hooks.** `connect` and every send with an address, on AF_INET and
  AF_INET6 sockets. A send without an address (a connected socket) is not
  judged; its destination was judged at `connect`. A connected UDP socket that
  sends to another address is judged at that send.
- **Address.** LSM tier: parsed by the address family, not the socket family:
  an AF_INET6 UDP socket accepts a `sockaddr_in`, and an AF_INET socket sends
  to a `sockaddr_in` whose family is AF_UNSPEC. An AF_INET6 raw or L2TP/IP
  socket sends to a `sockaddr_in6` whose family is AF_UNSPEC (the kernel reads
  it as AF_INET6); other AF_INET6 sends with AF_UNSPEC use the peer and are
  not judged. `connect` with AF_UNSPEC (disconnect) is not judged. An address that is not IPv4 or IPv6 gets the
  default. cgroup tier: the program (4 or 6) selects the address field, never
  the socket family; the kernel runs `sendmsg4` for an AF_INET6 socket that
  sends to an IPv4-mapped address or a `sockaddr_in`.
- **Deny** fails the connect or send with `EPERM` before it happens. Audit
  allows and reports.
- The decision (`network_policy.h`) takes only a slot, a destination and a
  protocol, so other hook types can share the maps.

## Known limits

- Host names, DNS, TLS and HTTP are not judged; the policy is CIDRs only.
- Unix and packet sockets and `bind`/`listen` are not judged. Raw sockets are
  not judged by the cgroup tier (see Program tiers).
- A task is judged by its cgroup at the time of the call (both tiers).

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
policy (`RuleNames`, `Origins`). Reporting is limited to 100 events per CPU per
second; enforcement is never throttled.
