# Sandbox policy http section: gateway redirect in node-agent (SUB-9947)

Step-level plan for the node-agent half of the sandbox gateway: the eBPF
redirect, the attribution tables, the per-pod health gate, the socket kill, the
workload lookup socket and the `http` block of the node status. It starts with
the result of the loader spike, because the spike picked the structure.

The work lands as six stacked pull requests. Each one has its own tests and
leaves `main` working with the feature off.

## Spike result

Question: can node-agent load `cgroup/connect4`, `connect6`, `sendmsg4`,
`sendmsg6`, sockops and a socket iterator from its own `cilium/ebpf` loader,
attached once at the cgroup root, next to the Inspektor Gadget runtime and the
BPF LSM programs of the `network` section?

Answer: yes for everything the spike could run. One part was checked by reading
the code and not by running it, and is listed under "Not shown yet".

What ran, on Linux 7.0.12 (arm64), as `go test` in the node-agent module with
the module's own `cilium/ebpf` replacement:

| Check | Result |
|---|---|
| All six program types load and attach at the cgroup root from one loader | pass |
| Attribution under port reuse: 2 pods, 8 processes each, 400 connections per process, half on IPv4 sockets and half on dual-stack sockets | 6,400 of 6,400 matched; `conns` empty after the run |
| A pod bound by its container cgroup, and a pod bound by the pod cgroup above the task | both attributed to the bound cgroup |
| An unbound pod, another address, another binding's address, an expired address, an exempt address, a binding that is failing open | all keep their own route |
| UDP to port 443 of an AI address | refused with EPERM; UDP to another address is sent; the refusal lifts while the gate is failing open |
| The loader exits; 20 more connections; a second loader starts | the 20 are redirected and counted, the second loader adopts the links and finds the maps with their content |
| Hook order: a BPF LSM `socket_connect` program on the same cgroup | it sees the original destination, and its deny returns EPERM before the redirect runs (the redirect counter does not move) |
| Socket kill: a connection opened before the bind | reset by the `bpf_sock_destroy` iterator; a connection to another address and a connection through the gateway stay open |

Why the two runtimes do not meet in the kernel: the gadgets in this repository
are LSM, tracepoint, raw tracepoint, socket filter and syscall programs, and
the gadget runtime attaches nothing at a cgroup. The redirect uses only cgroup
attach points and one iterator, through links, so several programs can share
the cgroup root with anything another agent (a CNI, for example) attaches
there.

### Not shown yet

- The redirect and the real `enforce_network` gadget were not run in one
  node-agent process. The hook order was shown with a stand-in LSM program on
  the same hook. PR 6 wires the redirect into the service and runs both.
- The GitHub runner's kernel may not have BPF LSM active. The hook-order test
  skips there and has to be run on a kernel that has it (it ran locally, and
  the EKS check repeats it).
- Nothing ran on a kernel below 6.5. The kill is a separate object so the
  redirect still loads there; that path has a unit test for the error only.

## Decisions the spike fixed

These are details the shared contract leaves open. Readers of the pinned maps
depend on them.

- Pin directory: `<host bpffs>/kubescape-sandbox/http/`, beside the pinned sets
  of the kernel sections. The four contract maps are pinned by name
  (`bindings`, `ai_dsts`, `conns`, `exempt`). The directory also holds the
  loader's own maps (`pending`, `cfg`, `stats`) and one `link_<program>` pin per
  attachment. Readers open only the four contract maps.
- Sizes and byte order are in `pkg/sandboxpolicy/httpgateway/layout.go`:
  `conns` key 18 bytes and value 40, `bindings` key 8 and value 8, `ai_dsts`
  key 20 and value 8, `exempt` key 20 and value 1. Integers are in host order,
  ports included. Addresses are 16 bytes in network order, IPv4 in its
  IPv6-mapped form. These are the sizes the gateway's processor already
  requires.
- `bindings` is keyed by the id of a bound cgroup. node-agent binds the pod
  cgroup and each container cgroup. The programs take the task's own cgroup,
  or else the nearest bound cgroup above it, so a task in a nested cgroup is
  still covered.
- `conns.cgroup` is the id of the cgroup whose binding matched. It is always a
  key of `bindings`, and the lookup socket answers for it.
- `conns.pid` is the thread group id as the initial pid namespace sees it.
- `ai_dsts` expiry is on the clock of `bpf_ktime_get_ns`. The value 0 never
  expires. The programs ignore an expired entry; removing it is the DNS feed's
  job.
- `exempt` stores an IPv4 prefix under its IPv6-mapped form, 96 bits longer.
- `conns` is an LRU hash of 65,536 entries.
- A `deny` pod's gate value stays 0 while the gateway is down. "Failing closed"
  is a status word only.
- On start the loader loads its programs again and swaps them into the pinned
  links (`BPF_LINK_UPDATE`). The maps are reopened, never recreated. There is
  no moment with nothing attached.
- The BPF objects are built with `bpf2go` and committed with their Go
  bindings, so building node-agent needs no clang. A make target rebuilds them
  in a pinned container.

## Pull requests

### PR 1: this plan, and kubescape/storage v0.0.418

- `docs/plans/2026-11-24-sandbox-http-gateway-redirect.md` (this file).
- `go.mod`: storage v0.0.418, which has `PolicySpec.HTTP` and `HTTPNodeStatus`.
  Nothing reads them yet.

### PR 2: programs, loader, pinned maps, attribution test

Package `pkg/sandboxpolicy/httpgateway`.

- `bpf/redirect.bpf.c`: maps and the five cgroup programs.
- `bpf/sockkill.bpf.c`: the iterator, its own object.
- `layout.go`: sizes, `Binding`, `Conn`, `ConnKey`, encoders and decoders.
- `loader_linux.go`: `Load(Options) (*Redirect, error)`, `(*Redirect).Close`,
  `Remove(dir)`, `SetGateway`, `SetBinding`, `Binding`, `DeleteBinding`,
  `SetAIDst`, `DeleteAIDst`, `AddExempt`, `Conns`, `Stats`.
- `sockkill_linux.go`: `(*Redirect).KillDirect(binding) (KillResult, error)`,
  `ErrKillUnsupported`.
- `redirect_bpfel.{go,o}`, `sockkill_bpfel.{go,o}`: generated.
- `Makefile`: `httpgateway-bpf` rebuilds the objects.
- `docs/features/sandbox-http-gateway-redirect.md`: what the programs do and
  the map layout.

Tests, failing first:

1. `layout_test.go`: each size constant equals the size of the map in the
   compiled object, and encode and decode round-trip known bytes. This is the
   test that breaks when the layout drifts from the processor's.
2. `redirect_linux_test.go` (root, cgroup v2, bpffs; skipped otherwise):
   `TestAttributionUnderPortReuse`, `TestOnlyBoundAIConnectionsAreTouched`,
   `TestRestartKeepsRedirecting`, `TestLSMSeesOriginalDestination`,
   `TestKillDirect`. Add real IPv6 to port 443 of an AI address (refused) and
   to another address (not refused).

### PR 3: bindings

Package `pkg/sandboxpolicy/httpgateway`, file `bindings.go`, with no kernel in
its unit tests (the map writer is an interface).

- Input per pod: the policies with an `http` section that select it and whose
  `spec.mode` is not `off`, the `sandbox.kubescape.io/gateway-prepared`
  annotation, the node's `rootFingerprint`, the rotation state.
- `Decide(pod, policies, root, rotation, now) Decision`: bound or not, the
  merged posture (`deny` wins), the policy references (UID, generation), and
  `needRestart` with its reason (no annotation, annotation lacks the node's
  root, annotation lacks `nextRoot` after `windowEnds` or under `emergency`).
- Binding ids: one per pod, stable while the pod lives, never reused while a
  `conns` entry still carries it. Stored in the `bindings` map itself, so a
  restart finds them.
- `Reconciler.Apply(decisions)`: writes and removes `bindings` entries for the
  pod cgroup and its container cgroups, removes a gone binding's `ai_dsts`
  entries, fills the static AI set from configuration (the DNS feed replaces
  it).
- `exempt`: service CIDRs, pod CIDRs (the reader the `network` section
  already has) and the node's addresses, plus configured extras.
- `rotation.go`: reads `rotation.json` from the ConfigMap
  `sandbox-gateway-trust`.

Tests: an unbound pod and a `mode: "off"` policy bind nothing; a pod without
the annotation is not bound and is listed for restart; two policies, one
`deny`, give a `deny` binding; at the end of a rotation window a pod without
the new root is unbound and listed, and bound again after its restart; the
exempt set holds the cluster ranges and the node addresses.

### PR 4: health gate, recovery, socket kill

File `gate.go`. The prober and the clock are interfaces, so the state machine
is tested without waiting.

- `Prober`: three GETs on the node address, port 18444 (`/healthz/envoy`,
  `/healthz/processor`, `/healthz/certs`), every 500 ms, 400 ms timeout.
- The gate opens on the first failed `envoy` or `processor` probe, when
  `canDecrypt` is false, or when the last known `decryptValidUntil` is under
  five minutes away. A failed `certs` probe alone sets `nodeControllerDegraded`
  and nothing else.
- Open: bindings with posture `allow` get gate 1. Bindings with posture `deny`
  keep 0.
- Recovery after 10 healthy seconds: gate 2 for the bindings that failed open,
  then the kill for each of them, then gate 0, then the status says coverage
  is restored. A failure during recovery goes back to gate 1.
- The kill runs in the pod's network namespace on a locked thread. On a
  host-network pod the namespace is shared with every other host-network
  workload, so the iterator must also check the socket's cgroup against the
  bound cgroups; until that check exists such a pod is not killed and is
  counted in `preAttachBypass`.
- Below Linux 6.5: no kill, `preAttachBypass` counted per pod.
- Interval, timeout, healthy time and certificate margin are configuration.

Tests: a `deny` pod keeps redirecting while an `allow` pod on the same node
goes direct; a connection opened in a fail-open window is reset on recovery,
and the reset comes before the status changes; the gate opens five minutes
before the last known expiry when `certs` stops answering, and not earlier; a
flap shorter than 10 seconds resets nothing; a failed `certs` probe alone
opens nothing.

### PR 5: workload lookup socket

File `lookup.go`: HTTP on the unix socket `/run/kubescape-sandbox/lookup.sock`.

```
GET /v1/workload?cgroup=<id>
200 {"namespace","pod","container","controller":{"kind","name"},
     "bindingId","policies":[{"uid","generation"}]}
404 when the cgroup is not bound
```

`container` is empty when the cgroup is the pod's. The socket is created with
mode 0660 and removed on shutdown; a stale socket file is replaced on start.

Tests: a bound container cgroup and its pod cgroup answer with the same
binding id; an unbound cgroup answers 404; a bad query answers 400; the answer
decodes with the processor's client struct (copied into the test).

### PR 6: status, restart, wiring

- `SandboxPolicyNodeStatus.http`: `boundPods`, `preAttachBypass`,
  `needRestart`, `gate`, `nodeControllerDegraded`, per policy.
- Start: `Load` adopts the pinned state, the kill does not run again for
  bindings that were already there, and the first probe goes out at once.
  While node-agent is down the gate keeps its last value.
- Uninstall and feature off: `Remove` runs with the kernel sections' pin
  removal.
- Configuration keys and `docs/CONFIGURATION.md`: the switch (off by default),
  the gateway and health ports, the timers, the static AI set, extra exempt
  ranges.
- `cmd/main.go` and `pkg/sandboxpolicy/integration`: the service starts the
  redirect when the switch is on.
- A run with the `network` section's gadget and the redirect in one process,
  repeating the hook-order test against the real gadget.

Tests: the status block for a bound pod, a pod that needs a restart and a
policy with no pod on the node; a restart keeps `conns` filling and does not
kill; the feature off removes the pins.

## What other tickets get

- The processor (SUB-9948) can replace its stub with the real maps after PR 2.
- The DNS feed (SUB-9950) writes `ai_dsts` through `SetAIDst` and `DeleteAIDst`
  after PR 2, and gets binding ids and each binding's hosts after PR 3.
- The tap (SUB-9953) reads `conns` after PR 2 with the layout above.

## Not in this ticket

- Chart changes: the hostPath for the lookup socket, the NetworkPolicy rule for
  port 18444, read access to the trust ConfigMap (SUB-9952).
- Limiting the gateway pod's own outbound connections (the card's comment of
  2026-11-22): where that rule lives is still to be settled with SUB-9952.
- Filling `ai_dsts` from DNS (SUB-9950).
