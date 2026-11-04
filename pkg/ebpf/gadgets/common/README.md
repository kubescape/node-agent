# Common enforcement library

Shared pieces of the BPF LSM enforcement gadgets (`enforce_privilege`,
`enforce_network` and `enforce_file` today).
They are taken from the enforce_exec gadget of the pinned Inspektor Gadget fork
and keep the first verdict fields, the mode encoding, the `counters` slots, the
identity type and the `bindings` key and value size. To move enforce_exec onto
the library, these still differ and need a decision: the `bindings` value is a
policy slot here (one instance per node) but 0 or a runtime mount namespace
inode in enforce_exec (one instance per container, restricted bindings);
enforce_exec reports allowed execs with
the policy mode (this library reports only denies), counts every allowed
decision, has restricted bindings and kernel-fault checks in its controller,
and keeps its path rules in an array that `policy.h` does not describe.

| File | Content |
|---|---|
| `bindings.h` | `bindings` map: cgroup id → the container's policy slot; optional parent-cgroup depth |
| `policy.h` | policy modes (0 off, 1 audit, 2 enforce), rank resolution (explicit deny > allow > default, one mode per rule), shared policy value |
| `verdict.h` | first verdict fields (`generation`, `cgroup`, `deny`, `mode`), per-CPU `counters` (denied, submitted, dropped, allowed, section error, rate limited), 100 reports per CPU per second |
| `arming.h` | arming rule: judge only tasks that executed outside the runtime mount namespace, and their children; `arming_faults`, tracking faults per slot |
| `merge/` | the merge contract for several policies on one container, and its shared test vectors |
| `enforcement/` | Go: the binding controller of one node-wide instance (policy written and frozen before any binding, live `Bind`/`Unbind` of a container to a slot, readiness, arming of tasks already running, `SlotFaults`) |

Section-specific parts (the policy key layout, hooks, compiler) stay in each
gadget.

## Build

`ig image build` mounts only the gadget folder, so `#include "../common/..."`
does not resolve by default. A gadget Makefile sets `IG_SOURCE_PATH` to the
repository root; the builder then mounts the whole repository. This reuses an
Inspektor Gadget variable meant for in-tree gadgets of the Inspektor Gadget
repository.
