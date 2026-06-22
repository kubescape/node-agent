# Alert Deduplication Bypass

`alertDeduplication.bypass` (config key `alertDeduplication::bypass`, default `false`)
is a master switch that disables **all** sensor-side alert suppression. When `true`,
config loading forces `eventDedup.enabled=false` (no raw eBPF event dedup) and
`ruleCooldown.ruleCooldownOnProfileFailure=false` (no per-signature rule cooldown), so
every rule firing is exported.

It is intended only for high-volume security-testing (DAST) scenarios where every
alert must surface. Under load it increases export volume and agent CPU — the intended
trade-off. Leave it off for all normal deployments.
