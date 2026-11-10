# Common enforcement library

Shared pieces of the BPF LSM enforcement gadgets (`enforce_privilege`,
`enforce_network`, `enforce_file` and `root_barrier` today).
They are taken from the enforce_exec gadget of the pinned Inspektor Gadget fork
and keep the first verdict fields, the mode encoding, the `counters` slots, the
identity type and the binding key and value size (the map is `sandbox_bindings`,
so it never collides with enforce_exec's `bindings` in one collection). To move
enforce_exec onto the library, these still differ and need a decision: the
binding value is a
policy slot here (one instance per node) but 0 or a runtime mount namespace
inode in enforce_exec (one instance per container, restricted bindings);
enforce_exec reports allowed execs with
the policy mode (this library reports only denies), counts every allowed
decision, has restricted bindings and kernel-fault checks in its controller,
and keeps its path rules in an array that `policy.h` does not describe.

| File | Content |
|---|---|
| `bindings.h` | `sandbox_bindings` map (version 1, gadget annotation `sandbox-bindings-version`): cgroup id → the container's policy slot and flags. Exact scope by default; `BINDING_SUBTREE` covers descendant cgroups, `BINDING_STRICT` carries the slot's class (a fault denies), `BINDING_RUNTIME_HELPERS` admits the arming exemption; opt-in `BINDINGS_DIRECT_LEVEL` (BPF LSM and tracing programs) reads the cgroup level with plain loads, and only when the task's own cgroup is not bound |
| `policy.h` | policy modes (0 off, 1 audit, 2 enforce), rank resolution (explicit deny > allow > default, one mode per rule), shared policy value |
| `verdict.h` | first verdict fields (`generation`, `cgroup`, `deny`, `mode`), per-CPU `counters` (denied, submitted, dropped, allowed, section error, rate limited), 100 reports per CPU per second |
| `root_barrier.h` | root barrier: always deny chroot, pivot_root, new user namespaces, new or joined mount namespaces and mount-tree changes for the tasks a gadget-defined predicate covers |
| `arming.h` | arming rule: judge only tasks that executed outside the runtime mount namespace, and their children; under `BINDING_RUNTIME_HELPERS` only, not those forked there by an unarmed runtime helper (OCI hooks). `arming_faults`: faults per slot; `arming_witness`: node faults and exempted execs. Include `bindings.h` first |
| `slots.h` | `sandbox_slot_state`: per slot one 8-byte value, generation << 1 \| active buffer. Each slot has two storage buffers (storage index = slot * 2 + buffer); the section's policy maps are keyed by the storage index. A hook reads the state with one load (`slot_storage`) and uses that storage index for every lookup of the call |
| `merge/` | the merge contract for several policies on one container, and its shared test vectors |
| `rootbarrier/` | Go: attestation (each barrier program has a live LSM link, BPF LSM is active) and a self-test, for the Ready step of a gadget that includes `root_barrier.h` |
| `enforcement/` | Go: the binding controller of one long-lived node-wide instance: live `Bind`/`Unbind` of a container to a slot; `Publish` of a slot's policy into its inactive buffer and one flip write (a failed publish keeps the last-good policy); `Free` and a quarantine (default 2 s) before a buffer is deleted or a slot reused; `Heal`/`HealNode` arm the bound tasks again without a reload; readiness, `SlotFaults`, `ArmingWitness`. A frozen mode (policy written and frozen before any binding) stays for sections not moved yet |

Section-specific parts (the policy key layout, hooks, compiler) stay in each
gadget.

## Build

`ig image build` mounts only the gadget folder, so `#include "../common/..."`
does not resolve by default. A gadget Makefile sets `IG_SOURCE_PATH` to the
repository root; the builder then mounts the whole repository. This reuses an
Inspektor Gadget variable meant for in-tree gadgets of the Inspektor Gadget
repository.
