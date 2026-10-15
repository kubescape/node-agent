# DNS baseline learning and matching

The DNS baseline is independent of `ingress` and `egress`. Each successful DNS
response with at least one answer contributes its lower-case, fully qualified
question name to `spec.dnsLookups`. Queries, unanswered responses and error
responses are excluded, including Kubernetes search-domain NXDOMAIN traffic.
DNS-only, cluster-internal and reverse names are included even if no connection
is observed. TXT/PTR answers need not contain IP addresses.

Each name keeps a set of executable paths and up to 16 distinct canonical IP
addresses as supporting evidence. Several names may share an IP. IP rotation
does not change the DNS match. Empty executable identity still contributes a
container-wide observation but cannot establish a process-specific match.

DNS uses the existing container learning lifecycle and
`maxSniffingTimePerContainer` (24 hours by default). There is no separate timer.
Completed, TooLarge and rejected containers cannot extend the DNS list, including
host containers whose other profiling consumers continue after completion.
Alerts never feed learning. New legitimate names require Risk Acceptance or
explicit relearning, not automatic acceptance after an alert.

`cp.was_dns_resolved(containerId, name)` answers the container-wide question.
`cp.was_dns_resolved_by_process(containerId, name, exepath)` requires the exact
executable path that learned the name. Neither reads the connection baseline.
DNS anomaly rules require a completed full profile (`profileDependency: 0`). Missing
profiles, profiles predating `dnsBaselineVersion: v1`, truncated DNS baselines,
size-limited (`TooLarge`) or partial profiles, and missing identity for process matching produce a profile-unavailable error,
not a negative match that could become an alert when negated. Existing profiles
must be explicitly relearned after upgrading; deploying a new agent alone does
not backfill historical DNS activity.

The name limit is 4096 per container learning window (retained across report
flushes) and per consolidated profile. Exceeding it sets
`dnsBaselineTruncated: true`; anomaly matching then stays silent until relearning.
The existing per-report byte limits still apply. Storage also counts DNS names,
executable paths and addresses toward its aggregate profile element-count limit;
exceeding that limit marks the profile `TooLarge` and disables DNS anomalies.
Addresses are unioned and capped again during storage consolidation. No parent
suffix collapsing broadens the set of learned names.

Learning follows existing workload/profile identity. Roll out image changes as a
new workload version/template so a new profile is learned. Changing the contents
behind a mutable image tag without changing the workload identity does not
reset a completed profile; request explicit relearning in that case. Host and
other stable identities likewise require explicit relearning for software
updates. This change adds no scheduled reset and changes no identity keys.

Rollout order: deploy DNS-aware storage, then the DNS-aware agent, relearn old
profiles, then enable rules using the new CEL helpers. After every agent has been upgraded,
reset profiles collected during mixed-version operation, including profiles
already carrying `v1`. Storage marks detected mixed-version aggregates unusable;
operators must still explicitly reset historical profiles instead of backfilling
or assuming that a version marker proves a complete DNS-aware learning window. Older agents cannot
compile the helpers, so rule rollout must be version-gated operationally.

DNS collector availability is part of baseline completeness. Disabled collection,
startup gaps, exhausted retries, and collector restarts invalidate overlapping
learning windows. Recovery does not repair those windows: explicitly relearn
with the DNS collector running throughout the new window.

DNS learning receives answered responses synchronously at the tracer capture
callback, before asynchronous event batching and DNS-manager lookups. A queued
response therefore cannot miss learning merely because its downstream delivery
happens after completion; genuinely post-completion observations stay excluded.
