# Profile Signing & Tamper Detection

User-supplied profile overlays (ApplicationProfile, NetworkNeighborhood, seccomp
profile, and rules) can be cryptographically signed and verified by node-agent.
When a signed profile is referenced by a pod and later modified, node-agent emits
an **R1016 "Signed profile tampered"** alert.

This complements the user-defined profile / overlay flow: a cluster operator signs
the profiles they hand-author, and node-agent re-verifies them on every cache load
so a post-signing edit (by an attacker or by accident) is detected.

## Components

| Piece | Location |
|---|---|
| Signing/verification core (cosign-backed) | `pkg/signature/` (`Signer`, `Verifier`, `cosign_adapter.go`) |
| Per-kind adapters (AP / NN / seccomp / rules) | `pkg/signature/profiles/` |
| Tamper detection + R1016 emission | `pkg/objectcache/containerprofilecache/tamper_alert.go` |
| Rule-signature verification on watch | `pkg/rulemanager/ruleswatcher/watcher.go` |
| `sign-object` CLI | `cmd/sign-object/` |

Backed by `kubescape/storage` #325; `go.mod` pins `kubescape/storage v0.0.291`.

## Signatures on the object

Signatures are stored as annotations on the signed object (`pkg/signature/annotations.go`),
under the `signature.kubescape.io` prefix:

- `signature.kubescape.io/signature`
- `signature.kubescape.io/certificate`
- `signature.kubescape.io/rekor-bundle`
- `signature.kubescape.io/issuer`
- `signature.kubescape.io/identity`
- `signature.kubescape.io/timestamp`

Both key-based (ECDSA) and keyless (Fulcio/Rekor/Sigstore) signing are supported
(`SignOptions.UseKeyless` / `WithPrivateKey`). Verification can optionally allow
untrusted material via `WithUntrusted` for testing.

## Configuration

`enableSignatureVerification` (config field `EnableSignatureVerification`,
default `false`) gates whether signature verification *gates* profile loading.

Tamper detection (R1016) runs whenever a signed user overlay is loaded and a
rule-alert exporter is wired (`SetTamperAlertExporter`, called from
`cmd/main.go`). When the exporter is nil, verification still runs and is logged
but no alert is emitted. A signed profile that verifies, or an unsigned profile,
is accepted; a profile whose signature is present but no longer valid triggers
R1016 and (when verification is enforced) is rejected.

The tamper key includes the resource version, so editing a resource re-flags it
on the next reconcile, while a long-lived broken profile only emits one R1016
across the cache lifetime.

## `sign-object` CLI

A standalone CLI (`cmd/sign-object/`, with its own `Dockerfile`) for signing,
verifying and inspecting signed objects out-of-cluster. Subcommands:

- `sign` — sign an object (default subcommand)
- `verify` — verify a signed object
- `generate-keypair` — produce an ECDSA keypair for key-based signing
- `extract-signature` — pull the signature material off an object

Supported object kinds: `applicationprofile` (`ap`), `seccompprofile` (`sp`),
`networkneighborhood` (`nn`), and `rules` (`r`).

## Tests

- `pkg/signature/` and `pkg/signature/profiles/` — unit + cluster-flow tests for
  the sign/verify round-trip and per-kind adapters.
- `pkg/objectcache/containerprofilecache/tamper_alert_test.go` — R1016 emission.
- `pkg/rulemanager/ruleswatcher/watcher_signature_test.go` — rule signature checks.
- Component tests `Test_29_SignedApplicationProfile`, `Test_30_TamperedSignedProfiles`,
  `Test_31_TamperDetectionAlert` in `tests/component_test.go`, plus signed-profile
  fixtures under `tests/resources/`.
