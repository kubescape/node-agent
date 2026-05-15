# Network-wildcards test fixtures

Living documentation for the `feat/network-wildcards` work.

Each `*.yaml` here is a complete `NetworkNeighborhood` document that exercises
ONE edge case in the v0.0.2 wildcard surface. The fixture-walk test
(`TestFixturesParse` + `TestFixturesMatchExpectedBehaviour` in
`pkg/rulemanager/cel/libraries/networkneighborhood/fixtures_test.go`,
plus the lab-side `Test_34_NetworkWildcardSurface`) consumes them
directly; users learning the syntax can copy-paste them as authoritative
examples.

**Note on `14-recursive-star-rejected.yaml`:** this fixture is intentionally
**rejected at admission** — it carries `dnsNames: ["**"]` to demonstrate
that the recursive-wildcard token is invalid v0.0.2 syntax. Don't `kubectl
apply` it; the apiserver will return a 400. The runtime matcher also
defends by silently dropping it on read, so a broken admission layer
won't accidentally let it through.

## Wildcard token vocabulary (matches paths + argv vocabulary)

| Token | Meaning |
|---|---|
| `⋯` (U+22EF, MIDLINE HORIZONTAL ELLIPSIS — single Unicode codepoint, NOT three ASCII periods) | Exactly one segment / argv position / **DNS label** |
| `*` leading | RFC 4592 wildcard — exactly one DNS label before the suffix |
| `*` mid-path | NOT used in DNS — use `⋯` instead |
| `*` trailing | One or more labels after the prefix (never zero — closes the apex blind spot) |
| `*` as `ipAddresses[i]` | Sugar for `0.0.0.0/0` ∪ `::/0` (any IP) |

## Field summary

| Field on `NetworkNeighbor` | v0.0.2 status | Match form |
|---|---|---|
| `ipAddress` (string) | **deprecated** — kept for back-compat | byte-equality only |
| `ipAddresses` (list of strings) | **new** | each entry: literal IP / CIDR / `*` sentinel; matches if ANY entry matches |
| `dnsNames` (list of strings) | normative | each entry: literal / leading-`*` / mid-`⋯` / trailing-`*`; matches if ANY entry matches |
| `dns` (single string) | **deprecated** since v0.0.1 | byte-equality only |
| `ports[]` | normative | name + protocol + port (uint16, nullable per §5.4) |
| `podSelector`, `namespaceSelector` | schema-level (passed through to auto-generated NetworkPolicy) | NOT consulted by the runtime CEL matchers — see §4.7 caveat |

## Fixture index

| # | File | Edge case |
|---|------|-----------|
| 01 | `01-literal-ipv4.yaml` | Single IPv4 literal in `ipAddresses[]` |
| 02 | `02-literal-ipv6.yaml` | IPv6 literal — verifier MUST canonicalise |
| 03 | `03-cidr-ipv4.yaml` | IPv4 CIDR — `10.0.0.0/8` covers a /8 range |
| 04 | `04-cidr-ipv6.yaml` | IPv6 CIDR — `2001:db8::/32` |
| 05 | `05-any-ip-sentinel.yaml` | The `*` sentinel — discouraged outside dev |
| 06 | `06-any-as-cidr.yaml` | `0.0.0.0/0` + `::/0` (RFC-aligned alternatives to `*`) |
| 07 | `07-mixed-ip-list.yaml` | Mixed list: literal + CIDR + sentinel — first match wins |
| 08 | `08-deprecated-ipaddress.yaml` | Backward compat — singular `ipAddress` field |
| 09 | `09-dns-literal.yaml` | Plain DNS literal with trailing dot |
| 10 | `10-dns-leading-wildcard.yaml` | `*.example.com.` — RFC 4592, exactly ONE label |
| 11 | `11-dns-mid-ellipsis.yaml` | `svc.⋯.cluster.local.` — exactly ONE label between |
| 12 | `12-dns-trailing-star.yaml` | `mycorp.com.*` — ONE OR MORE labels (never zero) |
| 13 | `13-dns-trailing-dot-normalisation.yaml` | `example.com` and `example.com.` MUST be equivalent |
| 14 | `14-recursive-star-rejected.yaml` | `**` — MUST be rejected by apiserver write strategy |
| 15 | `15-egress-and-ingress.yaml` | Both directions populated on same container |
| 16 | `16-egress-none.yaml` | NONE (`egress: []`) — declared zero-egress |
| 17 | `17-realistic-stripe-api.yaml` | Realistic external API call (Stripe) |
| 18 | `18-cluster-dns-via-mid-ellipsis.yaml` | The user's `svc.⋯.kubernetes.io.` use case |
| 19 | `19-port-protocol-with-cidr.yaml` | Ports + protocol + CIDR composed |
| 20 | `20-multi-container-mixed-wildcards.yaml` | Pod with multiple containers, each with different rules — combined real-world example |

## Expected behaviour matrix

The accompanying `expectations.json` (generated alongside) lists, per fixture,
the `(observedIP, observedDNS) → expected match result` triples that
`Test_34_NetworkWildcardSurface` walks.

## Migration note

Producers writing v0.0.2-conformant SBoBs SHOULD use `ipAddresses` (plural).
The singular `ipAddress` is retained ONLY for back-compat with v0.0.1-era
profiles; producers MUST NOT populate both on the same entry (the apiserver
admission strategy rejects this).

The deprecated `dns` (single string) field is retained for v0 compatibility;
v0.0.2 producers MUST emit `dnsNames` (list).
