# Runtime rule event processing

## preStop exec cache

The container profile helpers `cp.was_executed` and
`cp.was_executed_with_args` (also available under the legacy `ap.` prefix)
check for a cached preStop match by container ID. While that entry is live, a
fresh helper evaluation returns `true` for any exec in that container, regardless
of path or arguments. Rules that require these helpers to return `false` will
therefore skip the corresponding unexpected-path or unexpected-argument match.

The entry is created when a helper reaches the Pod spec fallback and the
evaluated path exactly matches an element of that container's
`lifecycle.preStop.exec.command` list. The fallback runs after the profile
lookup and match checks, and only reaches the hook check if the container's
main `command` did not match. The hook check compares individual list elements
regardless of the Pod's termination state or the exec's full argument vector.
For example, with `["/bin/sh", "-c", "sleep 5"]`, an ordinary `/bin/sh` exec
can start the window if evaluation reaches that fallback.
See the [exec helpers](../../pkg/rulemanager/cel/libraries/containerprofile/exec.go).

The hook-state entry expires **5 minutes** after insertion by default and can
be evicted earlier. The helpers also cache results for identical calls under
[`celConfigCache::ttl`](../CONFIGURATION.md#cel-configuration-cache) (default
`1m`), so a cached result can persist across the start or end of the hook-state
window. See the [preStop cache](../../pkg/rulemanager/cel/libraries/containerprofile/prestop_cache.go)
and [CEL helper bindings](../../pkg/rulemanager/cel/libraries/containerprofile/containerprofile.go).
The [default rules](../../tests/chart/templates/node-agent/default-rules.yaml)
include the unexpected-process rule (R0001) and the unexpected-arguments rule
(R0040), which use these helpers. See
[R0040 argument matching](inspektor-gadget-fork.md#r0040-argument-matching-b1)
for how the argument-aware helper compares recorded and observed arguments.

## eBPF event deduplication

The container watcher checks eligible events for duplicates before dispatch.
The [configuration](../../pkg/config/config.go) enables this by default through
`eventDedup.enabled`. The table gives the approximate TTLs, measured in 64 ms
buckets. A repeat hit keeps the original expiry, and another key can replace
the entry before expiry. See the [event handler](../../pkg/containerwatcher/v2/event_handler_factory.go),
[key builders](../../pkg/dedupcache/keys.go), and
[cache expiry logic](../../pkg/dedupcache/dedup_cache.go).

| Event | Key fields | TTL |
| --- | --- | --- |
| Open | Mount namespace ID, PID, path, raw open flags | 10 s |
| Network | Mount namespace ID, PID, reported endpoint address, destination port, protocol | 5 s |
| DNS (forwarded queries and error responses) | Mount namespace ID, PID, DNS name, query/response indicator, query type, response code | 5 s |
| Capabilities | Mount namespace ID, PID, capability, syscall | 10 s |
| HTTP | Mount namespace ID, PID, direction, method, host, URL path, raw query | 2 s |
| SSH | Mount namespace ID, destination IP, destination port | 10 s |
| Symlink | Mount namespace ID, PID, old path, new path | 10 s |
| Hardlink | Mount namespace ID, PID, old path, new path | 10 s |
| Ptrace | Mount namespace ID, PID, executable path | 10 s |
| Syscall | Mount namespace ID, PID (always 0 for now), syscall | 5 s |

Other event types, including exec, skip the dedup cache. So do answered DNS
responses and HTTP events missing a request or URL. See the
[event eligibility checks](../../pkg/containerwatcher/v2/event_handler_factory.go).

Syscall events have no PID yet: `GetPID` returns 0 for them until the gadget
adds process enrichment (see the [workaround](../../pkg/utils/datasource_event.go)).
All processes in a mount namespace therefore share one syscall key, so when a
second process makes the same syscall within 5 s, rule evaluation skips it.

The network key omits packet direction. For the network gadget, the endpoint
address is the remote peer and the port is the packet's destination port.
Ingress and egress events can share a dedup key when all listed fields match,
so direction-sensitive rules may see only the first event within the TTL.
See the [network gadget](../../pkg/ebpf/gadgets/network/program.bpf.c) and
[event accessors](../../pkg/utils/datasource_event.go).

Duplicates skip CEL rule evaluation and, for event types handled by those
consumers, container profile learning and malware scanning. Network events
are registered for profile learning, rule evaluation, network streaming, and
metrics. Duplicate network events still reach the network stream and metrics.
The watcher also forwards regular duplicates to registered third-party
receivers and continues rule policy reporting for symlink and hardlink events.
Duplicate rule-only DNS events have no downstream consumer. See the [handler routing](../../pkg/containerwatcher/v2/event_handler_factory.go)
and [rule manager's duplicate check](../../pkg/rulemanager/rule_manager.go).
