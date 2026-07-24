# Network endpoint fixtures — ContainerProfile (user-defined-profile) form

These are the **ContainerProfile** authoring examples for the network egress/
ingress surface — the "new way" (migration #862) of authoring a user-defined
behavioural allow-list. Each file is a copy-pasteable, self-documenting example
of one edge case in the v0.0.2 network-endpoint grammar.

## Relationship to `../network-wildcards/`

`../network-wildcards/*.yaml` hold the same edge cases as **NetworkNeighborhood**
documents (per-workload: `spec.containers[]`). Those are consumed as-is by the
CEL matcher unit tests (`pkg/rulemanager/cel/libraries/networkneighborhood/
fixtures_test.go`) and must stay in NN form.

The files **here** are the migrated, user-authorable equivalents:

| NetworkNeighborhood (learned / legacy) | ContainerProfile (user-authored, new) |
|---|---|
| per-**workload** | per-**container** |
| `spec.matchLabels` + `spec.containers[].{egress,ingress}` | `spec.matchLabels` + `spec.{egress,ingress}` directly |
| bound by workload selector | bound by pod label `kubescape.io/user-defined-profile: <name>` |
| carries `managed-by/status/completion` annotations | **no annotations** — name (+ namespace, injected) only; a signature is added by the signing tool |

A multi-container NN (fixture 20) becomes **one CP document per container**,
`---`-separated in the same file.

## Contents

- `00-fusioncore-homoglyph-attack.yaml` — flagship security example: a pinned
  single-vendor allow-list and the look-alike (homoglyph) domains it rejects.
- `01`–`20` — the network-endpoint edge cases (literal IPv4/v6, CIDR, the `*`
  any-IP sentinel, mixed lists, deprecated singular `ipAddress`, DNS literals,
  leading-`*` / trailing-`*` / mid-`⋯` wildcards, trailing-dot normalisation,
  the rejected recursive `**`, egress+ingress direction isolation, ports/
  protocols, cluster-DNS via mid-`⋯`, and a multi-container split).

## Wildcard token vocabulary

| Token | Meaning |
|---|---|
| `⋯` (U+22EF, single codepoint — NOT three ASCII periods) | exactly one DNS label between fixed anchors |
| `*` leading | RFC 4592 wildcard — exactly one label before the suffix |
| `*` trailing | one or more labels after the prefix (never zero) |
| `*` as an `ipAddresses[i]` entry | sugar for `0.0.0.0/0` ∪ `::/0` (any IP) |

## Authoring rules these examples follow

- User-managed ContainerProfiles carry **only** `metadata.name` (namespace is
  injected by tooling). No `managed-by`, no `status/completion` — those are
  meaningless on an authored profile; the read path forces the enforcement
  state for a label-referenced CP.
- `14-recursive-star-rejected.yaml` is **intentionally invalid** (`dnsNames:
  ["**"]`) — do not `kubectl apply` it; it documents that recursive `**` is
  not v0.0.2 syntax.
