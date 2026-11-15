# Node-agent profile comparison, 27 October 2026

This follows [#1052](https://github.com/kubescape/node-agent/pull/1052) and
corrects the query used in its inconclusive comparison. No production
node-agent collection behavior changes in this PR.

## Why the earlier positive control appeared empty

The earlier collector inspected `kubectl get containerprofiles -o json`.
Storage's default LIST returns metadata without profile bodies; typed responses
can contain null exec/open fields. Individual GETs retrieve the behavior data.
A null field in that LIST is therefore not evidence of an empty stored profile.
The original report and summary are retained, with a correction pointing here.

In the resumed environment, an individual GET for the earlier ordinary workload
returned a BusyBox exec entry even though the LIST entry had none. The fresh
comparisons below use new Pod names and fetch each matching profile individually.
The read-only collector also verifies that GET and LIST identities match and
rejects profiles created before the current Pod.

## Results

The same released node-agent observed two fresh pairs of ordinary and gVisor
Pods. Both pairs run the same pinned BusyBox image. A fail-fast shell runs three
`/bin/busybox true` calls, prints a harmless JSON completion marker, then waits
before exiting. All four workloads exited 0 and produced that marker. Exact
container IDs were checked independently against K3s containerd records.

| Pair | Ordinary target exec in individual GET | gVisor matching profile / target exec |
|---|---|---|
| [First](evidence/first.json) | Present | No matching profile / not observed |
| [Second](evidence/second.json) | Present | No matching profile / not observed |

The LIST entries in both ordinary positive controls reported zero exec entries.
Individual GETs returned the target exec. Profiles deduplicate command entries:
**an entry proves observation of that command signature, not a count of three
exec calls**. The summaries retain booleans and entry counts, not argv or raw
profile bodies.

This establishes a narrow difference in the deployed node-agent's profile output
on this self-managed ARM64 setup. It does not isolate the cause to kernel hooks:
gVisor container discovery, identity enrichment and profile admission can also
prevent output. An absent gVisor profile does not prove that every underlying
host event was absent. The earlier independent bpftrace experiment remains a
separate host tracepoint comparison, not a node-agent event export.

## Environment and procedure

The [environment summary](evidence/environment.json) records component image
IDs, selected configuration, readiness and tracer startup timestamps. The
node-agent watcher started before the reported workloads.

- Dedicated Multipass Ubuntu 24.04.5 ARM64 VM, 4 vCPUs, 6 GiB RAM, kernel
  6.8.0-147-generic; no managed GKE or x86_64 validation.
- K3s v1.37.1+k3s1 with its own containerd socket at
  `/run/k3s/containerd/containerd.sock`.
- Official node-agent v0.3.293, storage v0.0.348, chart 1.40.5.
- gVisor release-20261019.0, systrap, `io.containerd.runsc.v1`.
  The ordinary containers use `io.containerd.runc.v2`.
- Runtime observability enabled, runtime detection disabled, namespace allowlist
  `gvisor-comparison`, initial profile delay 5s and update period 5s.

This resumes the experimental installation documented in the previous report,
including its test-only root storage workaround and K3s IG socket override.
Those are not production chart recommendations. The gVisor runtime used for
this Kubernetes comparison has no SecCheck sink; this is a baseline for the
existing node-agent path, not integration of the new receiver.

The API, storage, node-agent and ordinary positive control worked for these
queries. This does not certify the whole chart/image combination, every tracer
or all components in the cluster. The previous report's interrupted-read fix
was not changed or retested here, and the historical missing start's cause
remains unproven.

## Reproduce and collect

Use the dedicated disposable Linux VM and the existing runtime/agent setup
from the [previous report](../gvisor-start-loss-20261026/README.md).
Keep kubeconfig and credentials private. The read-only collector is specific
to a local K3s experiment; it neither installs components nor changes resources.

1. Confirm the `gvisor` RuntimeClass uses the configured runsc handler, the
   agent uses K3s's containerd socket, and its namespace allowlist includes
   `gvisor-comparison`. Wait for storage and node-agent readiness, plus watcher
   and exec tracer startup. Readiness alone is not behavioral validation.
2. Apply `workloads-a.json`, then wait for both Pods to complete. Use fresh
   Pod names for another run. Reusing names can mix a previous profile with
   the current Pod; the collector rejects a profile predating the Pod.
3. Copy `scripts/collect-gvisor-profile-comparison.py` into the VM and run:

   ```sh
   sudo python3 collect-gvisor-profile-comparison.py \
     --namespace gvisor-comparison \
     --ordinary-pod ordinary-20261027-first \
     --gvisor-pod gvisor-20261027-first \
     --output /absolute/new/first.json
   ```

4. Apply `workloads-b.json` and repeat with the second Pod names and a new
   output file. The output path must not already exist. Keep negative results.
5. A failed ordinary positive control produces an inconclusive report and
   exit status 1. Exit status 0 means the ordinary control passed; inspect the
   report to see whether gVisor also produced an observation. API failures,
   profile identity changes, wrong runtimes, missing completion markers and
   failed workloads fail closed.
6. Remove only the experiment Pods or its dedicated namespace after retaining
   the summaries. Stop the VM when finished; preserve the installation for
   follow-up. Do not delete the broader `kubescape` namespace for cleanup.

The collector uses LIST only to discover names and workload identity, then GET
for evidence. It exports no raw API errors, kubeconfig, service-account tokens,
profile arguments or unrelated exec paths. The harmless target signature is
compared in memory and represented by a boolean.

## What this unblocks and what remains

The ordinary positive control now works, and the query defect in the previous
report is explained. This gives a concrete baseline for reviewing opt-in
receiver integration. It does not supply CRI/Kubernetes metadata joining, an
export route for verified starts, source-health reporting, per-sandbox fairness,
stop signals, network semantics, overhead measurements or production support.
Those remain separate deliverables under the accepted experiment. No claim of
per-actor attribution or in-sandbox enforcement is made.

## Validation

The eight focused Python collector tests cover metadata-only LISTs, misleading
LIST bodies, runtime verification, failed workloads, changed profile identity,
stale profiles, missing completion markers, and privacy of exported summaries. The existing trial checker
suite also passes. Live evidence is limited to the two pairs recorded here;
this docs/tooling change does not claim a Go build or full repository test run.
