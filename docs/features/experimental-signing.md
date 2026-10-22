# Experimental artifact signing

Artifact signing is an opt-in build feature. Regular node-agent builds exclude
signature verification, trust-policy reload, signed configuration loading, and
`/policyz`. Setting signing configuration in a regular build does not enable it.

Build the experimental agent with:

```sh
make binary BUILD_TAGS=experimental_signing
# Or:
go build -tags experimental_signing -o node-agent ./cmd
make docker-build-only BUILD_TAGS=experimental_signing
```

Build the optional signing CLI with `go build -tags experimental_signing -o
sign-object ./cmd/sign-object`. Compile the `./cmd` package rather than the
single `cmd/main.go` file so build-specific startup helpers are included.

In an experimental build, `enableSignatureVerification` enables legacy signed
profile verification. Set `bundleTrustPolicyPath` to a mounted root-signed trust
policy to configure signed profile bundles, Rules, and rule bindings. The root
anchor comes from `/etc/bundle/root.pub` or the compiled root; the published demo
root is unsuitable for authenticating production artifacts.

The agent loads `config.signed.json` from the configuration directory and
`/etc/config/clusterData.signed.json` when present. Invalid signed configuration
is rejected instead of falling back to unsigned content. With no signed files,
the existing unsigned configuration paths remain available.

Trust-policy reload runs periodically. An invalid policy at startup leaves
signing disabled until a valid policy is mounted. A rejected reload preserves
the policy already in force. Rules are resynchronized after policy reload;
bindings re-evaluate on their next binding event. `/policyz` on the health port
reports policy identity and counts, without exposing signer lists or policy
contents, and returns 404 before a policy is in force.

Flat profiles use the legacy signature check, which accepts self-signed
certificates and detects content changes; it does not authorize the signer
against bundle fragment classes. Use signed bundles with a real trust root when
signer authorization is required. This remains experimental.

Bundle fragments currently support flat profile specs only. Fragments with
nonempty `containers`, `initContainers`, or `ephemeralContainers` are rejected
before assembly, including when these fields occur in embedded signed content.
Standalone signed grouped profiles remain supported by legacy verification.

Stored-spec divergence is logged as a diagnostic; it does not emit R1017. Signed
embedded content governs instead of the mutable stored spec. A verified embedded
spec that cannot be decoded is refused in both modes. Signing refusal
clears the previously admitted flat profile and retains its reference for
recovery. Failed bundle reassembly retains a composite only while the policy that verified
it remains in force. Unverified cached content is cleared on assembly failure;
a policy replacement requires fresh verification. While enforcing, source-fetch
errors retain only previously verified profiles or eligible verified composites.
Refresh uses the original pod label to discover bundles and retains the resolved
flat-profile reference for recovery. R1018 is emitted only after a profile is
actually adopted.

This feature does not require RogueArtifact CRDs or the RogueArtifact writer
from PR #121. R1017 remains owned by that separate work; signing does not register
or emit an R1017 rule.

Run both build variants when changing this feature:

```sh
go test ./pkg/config ./pkg/healthmanager ./pkg/objectcache/containerprofilecache ./pkg/rulebindingmanager/cache ./pkg/rulemanager/rulecreator ./pkg/rulemanager/ruleswatcher ./pkg/rulemanager/types/v1
go test -tags experimental_signing ./pkg/config ./pkg/healthmanager ./pkg/signature/...
go build -o /tmp/node-agent-default ./cmd
go build -tags experimental_signing -o /tmp/node-agent-signing ./cmd
```
