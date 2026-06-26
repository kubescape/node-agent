# Network Wildcards (CIDRs, wildcards, and plural IP/DNS)

The CEL `networkneighborhood` library matches observed connections against the
`NetworkNeighborhood` profile. As of storage `v0.0.2` the IP and DNS surfaces
accept wildcard, CIDR, and list-valued entries instead of byte-exact strings
only. This lets a profile describe a *range* of allowed peers (a CIDR, a DNS
subdomain family, "any IP") rather than enumerating every literal.

The matching logic lives in
`pkg/rulemanager/cel/libraries/networkneighborhood/network.go` and delegates the
wildcard/CIDR semantics to `kubescape/storage`'s `networkmatch` package
(`MatchIP` / `MatchDNS`). Node-agent pins `kubescape/storage v0.0.290`, which
carries storage [#324](https://github.com/kubescape/storage/pull/324).

## IP matching (`ipAddresses`, `ipAddress`)

`matchIPField` checks, cheapest first:

1. Exact string equality against the profile's `Values` set.
2. Canonicalised IP equality — a single `net.ParseIP`, so observed
   `::ffff:10.0.0.1` matches a profile entry of `10.0.0.1`, and expanded IPv6
   matches compact IPv6.
3. `networkmatch.MatchIP` over the full entry set, which matches literals,
   CIDRs and the `*` sentinel uniformly.

Accepted `ipAddresses[]` entry forms:

| Form | Example | Meaning |
|---|---|---|
| Literal IPv4/IPv6 | `162.0.217.171`, `2001:db8::1` | exact host |
| CIDR | `10.0.0.0/8`, `2001:db8::/32` | any host in range |
| `*` sentinel | `*` | sugar for `0.0.0.0/0` ∪ `::/0` (any IP) — discouraged outside dev |

A match succeeds if **any** entry matches. The singular `ipAddress` (string)
field is deprecated and kept for back-compat; it is matched by byte-equality
only. Producers MUST NOT populate both `ipAddress` and `ipAddresses` on the
same entry.

## DNS matching (`dnsNames`, `dns`)

`matchDNSField` first normalises the FQDN trailing dot (spec §5.8): `example.com`
and `example.com.` are equivalent. It then runs `networkmatch.MatchDNS` over the
full entry set for the wildcard forms:

| Token | Example | Meaning |
|---|---|---|
| Literal | `api.stripe.com.` | exact name |
| Leading `*` | `*.example.com.` | RFC 4592 — exactly **one** label before the suffix |
| Mid `⋯` (U+22EF) | `svc.⋯.cluster.local.` | exactly **one** label in that position |
| Trailing `*` | `mycorp.com.*` | **one or more** labels after the prefix (never zero) |

`⋯` is the single Unicode codepoint MIDLINE HORIZONTAL ELLIPSIS, **not** three
ASCII periods. The recursive token `**` is invalid v0.0.2 syntax: the apiserver
rejects it at admission, and the runtime matcher additionally drops it on read.
A match succeeds if **any** entry matches. The singular `dns` (string) field is
deprecated; v0.0.2 producers MUST emit `dnsNames` (list).

## Port/protocol matching

`wasAddressPortProtocolInEgress` / `...Ingress` validate the port range
(0–65535) and protocol type, but the port/protocol projection
(`AddressPortsByAddr`) is out of scope for the current projection-v1 layer, so
these matchers **degrade to address-only** matching. Wildcard/CIDR IP semantics
are still enforced via `matchIPField`.

## Default rule change

This feature enables the **"Unexpected Egress Network Traffic"** rule
(`R0011`) by default in
`tests/chart/templates/node-agent/default-rules.yaml`. R0011 fires on egress
that is not whitelisted by the application/network profile; the wildcard surface
above is what producers use to whitelist legitimate ranges without enumerating
every IP.

## Tests

- `pkg/rulemanager/cel/libraries/networkneighborhood/wildcard_test.go` and
  `fixtures_test.go` — unit coverage of the match semantics.
- `tests/resources/network-wildcards/` — 20 declarative `NetworkNeighborhood`
  fixtures, one per edge case, with a `README.md` token/field reference.
- `Test_28_UserDefinedNetworkNeighborhood` in `tests/component_test.go` — an
  end-to-end component test of a user-defined NetworkNeighborhood.
