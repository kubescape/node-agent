# Syscall Tracer: On-Demand Fetching

Container profiles could end up with 0 or partial syscalls even when the container executed
tens of distinct syscalls (kubescape/node-agent#922). This documents the root cause and the fix,
including why the fix ended up restoring the pre-PR-#591 architecture's shape rather than
tuning the post-#591 one.

## Background: how this worked before PR #591

Before PR #591 ("Feature/refactor container watcher"), node-agent used a **non-destructive**
`Peek(mntns)` on the vendored native seccomp tracer (`pkg/gadgets/advise/seccomp/tracer`, old
`amirmalka/inspektor-gadget` fork): a plain `bpf_map_lookup_elem`, no delete. Two independent
consumers each registered this same callback and drove it on their own schedule:

- `ContainerProfileManager` called it on demand, exactly when saving a profile (periodic
  checkpoint or termination) — never on a timer of its own.
- `RuleManager` ran its **own 5-second ticker per monitored container**
  (`pkg/rulemanager/v1/rule_manager.go`, `syscallPeriod = 5 * time.Second`) purely for real-time,
  syscall-based rule alerting, fully decoupled from profile-saving.

PR #591 moved the tracer to the OCI-gadget framework (`advise_seccomp` image), whose generic
map-iterator mechanism (`GADGET_MAPITER`, `pkg/operators/ebpf/maps.go` in the
`matthyx/inspektor-gadget` fork) reads batches via `BPF_MAP_LOOKUP_AND_DELETE_BATCH` — a
destructive drain. The refactor consolidated to a single shared tracer instance with one
internal periodic fetch (`operator.oci.ebpf.map-fetch-interval`, ended up at `30s`) whose decoded
events fan out to every consumer (`ContainerProfileManager`, `RuleManager`, metrics) alike. That
single shared schedule is what regressed rule-alerting latency from the original 5s to 30s, and
is also what caused #922: a container terminating between two 30s ticks lost whatever it
executed since the last one, because nothing else could recover it before the container's data
was removed.

Note: the destructiveness of the read was never actually why a single shared schedule was
required — nothing stops running two independent instances of the same gadget image, each
with its own attach and its own private map, at different cadences. The real reason a single
schedule existed is simpler: there was only one tracer instance and one internal ticker driving
it, and every consumer got whatever cadence that one ticker happened to use.

## The fix

Rather than picking a single fixed interval that compromises between "fast enough for alerting"
and "cheap enough to not matter," the tracer's own internal fetch schedule is removed entirely,
and *all* fetching — periodic or not — goes through one explicit call:

- **`ebpfoperator.TriggerManualMapFetch(names ...string)`** (added in
  `matthyx/inspektor-gadget#12`) requests an immediate, out-of-band fetch from a running map
  iterator, independent of any schedule. The OCI gadget is started with
  `map-fetch-interval: "0"` and `map-fetch-count: "0"`, which — per `maps.go`'s iterator loop —
  disables its own ticker entirely; the iterator then does nothing except wait to be triggered
  (plus the existing flush-on-stop safety net when the whole gadget shuts down).
- **`SyscallTracer.Peek()`** (pkg/containerwatcher/v2/tracers/syscall.go) calls that trigger.
- **`SyscallTracer.runPeekLoop`**, started in `Start`, calls `Peek` on `syscallPollInterval`
  (default `5s`, matching the original `RuleManager` cadence) — this is what now drives live
  event delivery to every consumer (profile-building and rule alerting alike), restoring the
  original alerting responsiveness. Unlike the pre-#591 design, this is **one global ticker**
  regardless of how many containers are being traced (the old design ran one 5s ticker *per
  container*), since one `TriggerManualMapFetch` call drains and dispatches every currently
  tracked container's pending syscalls in a single batch.
- **`ContainerProfileManager.SetSyscallFlusher`** lets `TracerFactory` additionally wire
  `Peek` to be called once more, out of that schedule, right before a container's final forced
  profile save (`flushAndSettle` in pkg/containerprofilemanager/v1/helpers.go, called from both
  termination paths in monitoring.go) — closing even the up-to-`syscallPollInterval` gap the
  periodic schedule alone would still leave at exactly the moment a container disappears.
  `flushAndSettle` waits a fixed `postSyscallFlushSettleDelay` (`500ms`) afterward for the
  resulting events to travel through the event queue/worker pool into the container's data
  before it's snapshotted and cleared. This wiring only happens when the syscall tracer is
  actually enabled (`SyscallTracer.IsEnabled`), so a disabled tracer costs nothing.

## Why this isn't a regression risk for alerting

`SyscallEventType` events fan out to `RuleManager` and a metrics counter through the generic
per-event pipeline (`pkg/containerwatcher/v2/event_handler_factory.go`). `RuleManager` evaluates
rules against each syscall event in real time and drives rule-based alerts through
`pkg/ruleadapters/adapters/syscall.go` (e.g. "unexpected syscall executed"), including
post-learning while `EnableRuntimeDetection` keeps the tracer running. Removing the periodic
schedule entirely (fetching only at `ContainerProfileManager`'s own save points, which happen
every `updateDataPeriod` — default 10 minutes — or at termination) would have delayed that
alerting path by the same amount, which is why `syscallPollInterval` still drives a real,
independent periodic `Peek()` call — it isn't only there for `ContainerProfileManager`
(see [Batching](#batching-bypassing-the-generic-pipeline-for-containerprofilemanager) below for
why `ContainerProfileManager` is no longer one of that fan-out's targets).

## Batching: bypassing the generic pipeline for ContainerProfileManager

`SyscallTracer.callback` decodes one eBPF fetch into a batch of syscall names per container. The
generic pipeline models one event per occurrence, so turning that batch into individual
`SyscallEventType` events (one `AddEventDirect`, dedup-key computation, and 2-handler dispatch
loop each) is pure per-item overhead for a data source that was never actually a discrete event
stream — it's a periodic snapshot of a persistent per-mntns bitmap. That overhead scales with how
many *distinct* syscalls a container has executed since its last fetch, which is worst right
after a container starts.

`RuleManager`'s rule matching and the generic dedup cache both key off a single
`event.syscall` value, so they still need one event per syscall — batching can't safely change
that without a breaking rule-schema change (a list field with `in`/`exists` semantics instead of
scalar `==`). `ContainerProfileManager` has no such constraint: it only ever folds each syscall
into a per-container `mapset.Set[string]`, so `SyscallTracer.callback` calls
`ContainerProfileManagerClient.ReportSyscalls(containerID, syscalls []string)` directly — a
single container-lock acquisition and size update for the whole batch — instead of emitting a
separate event per syscall for it to pick up off the queue. `containerProfileManager` is
correspondingly absent from `ehf.handlers[utils.SyscallEventType]`; `RuleManager` and `metrics`
are unaffected and still receive one event per syscall exactly as before.

Two things this direct call requires that the generic pipeline used to provide for free:

- **Filtering out unresolved container IDs.** The map covers every mount namespace on the node,
  including ones never resolved to a container (host processes, etc.) —
  `EventHandlerFactory.ProcessEvent`'s `if enrichedEvent.ContainerID == "" { return }` used to
  drop those before they ever reached `ReportSyscall`. `callback` now does that check itself
  before calling `ReportSyscalls`, to avoid spamming `ContainerProfileManager.withContainer`'s
  "invalid empty containerID" error on every such row, every tick.
- **Not blocking the shared fetch-processing path.** Previously `ReportSyscall` reached
  `ContainerProfileManager` through the generic queue and one of `WorkerPoolSize` pooled
  goroutines, so a slow or blocked container only ever tied up one interchangeable worker.
  `callback` is invoked synchronously, once per currently-traced container, by the single
  goroutine that processes each fetch — and `ContainerProfileManager.ReportSyscalls` can itself
  block (`withContainer` sends on a container's `SyncChannel`, which is bounded, while holding
  that container's lock, when a profile crosses `MaxTsProfileSize`). `callback` therefore
  dispatches `ReportSyscalls` on its own goroutine rather than calling it inline, so one
  container's backpressure can never stall the processing of every other container's syscalls
  for that tick, or the next `Peek`-triggered fetch.

## Concurrency

`ContainerProfileManager.syscallFlusher` (the callback `SetSyscallFlusher` registers) is stored
via `atomic.Pointer[func()]`, not a plain field. `SetSyscallFlusher` is called once during
startup wiring (`TracerFactory.CreateAllTracers`), but by that point `StartContainerCollection`
has already begun enumerating existing containers and starting their `monitorContainer`
goroutines — a container that starts and terminates in that window would call `flushAndSettle`
(reading `syscallFlusher`) concurrently with that write. A plain field would be an unsynchronized
data race there, silently able to reintroduce #922's exact bug at exactly the highest-churn
moment there is: node-agent startup or restart.

## Known limitations

`TriggerManualMapFetch` is fire-and-forget and `flushAndSettle`'s settle delay is a bounded wait
for the event pipeline, not an absolute guarantee tied to the fetch itself. Under severe
scheduler contention or a saturated event queue, the flushed events could in principle still
arrive after the delay elapses; termination would then fall back to whatever the tracer already
had from the last periodic `Peek` (at most `syscallPollInterval` old) — the same kind of race as
before, just far less likely and far smaller in scope than the original 30-second window.
