# Common enforcement library

Shared pieces of the BPF LSM enforcement gadgets (`enforce_privilege`,
`enforce_network`, `enforce_file` and `root_barrier` today).
They are taken from the enforce_exec gadget of the pinned Inspektor Gadget fork
and keep the first verdict fields, the mode encoding, the `counters` slots, the
identity type and the binding key and value size (the map is `<section>bindings`,
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
| `bindings.h` | `<section>bindings` map (version 1, gadget annotation `sandbox-bindings-version`, which the controller checks at instance start): cgroup id → the container's policy slot and flags. Exact scope by default; `BINDING_SUBTREE` covers descendant cgroups, `BINDING_STRICT` carries the slot's class (a fault denies), `BINDING_RUNTIME_HELPERS` admits the arming exemption. `enforcement.PendingSlot` (0xFFFFFFFF) is a slot that is never published: the program finds no policy there, so for a judged task a Strict pending binding fails closed (a structural fault, EPERM) and an Audit one allows; both count only in the node-wide section error counter, with no per-slot counter (`SlotFaults`/`Counters(PendingSlot)` return an error); its class is the binding's own (`Binding.Strict`, refused on a real slot), and a class flip of a real slot never rewrites it |
| `policy.h` | policy modes (0 off, 1 audit, 2 enforce), rank resolution (explicit deny > allow > default, one mode per rule), shared policy value |
| `verdict.h` | first verdict fields (`generation`, `cgroup`, `deny`, `mode`), per-CPU `counters` (denied, submitted, dropped, allowed, section error, rate limited), 100 reports per CPU per second |
| `root_barrier.h` | root barrier: always deny chroot, pivot_root, new user namespaces, new or joined mount namespaces and mount-tree changes for the tasks a gadget-defined predicate covers |
| `arming.h` | arming rule: judge only tasks that executed outside the runtime mount namespace, and their children; under `BINDING_RUNTIME_HELPERS` only, not those forked there by an unarmed runtime helper (OCI hooks). The exec mark is created in `bprm_check_security` (where a Strict binding can refuse the exec) and only set in `bprm_committed_creds`. `arming_faults`: faults per slot; `arming_unevaluated`: judgements an Audit binding lost, per slot; `arming_attempts` (per CPU): judged checks and forks of armed tasks, per slot, the denominator of the fail rate; `arming_witness`: node faults and exempted execs. `arming_fail_fork_marks` and `arming_fail_exec_marks` are test-only switches. Include `bindings.h` first |
| `slots.h` | `<section>slot_state`: per slot one 8-byte value, generation << 1 \| active buffer. Each slot has two storage buffers (storage index = slot * 2 + buffer); the section's policy maps are keyed by the storage index. A hook reads the state with one load (`slot_storage`) and uses that storage index for every lookup of the call |
| `creds.h` | `<section>creds` and `<section>cred_counts`: the workload's credentials by address, with a quota per binding. Added from `cred_prepare` and `uring_override_creds` for a task of a binding, and by `CRED_WALK_PROGRAM` for the tasks of a binding at bind and heal (the owner runs it, `enforcement.Config.CredWalk`); deleted from `cred_free`. A hook judges overridden credentials only when they are in the record, so an io_uring request under the workload's credentials is judged and overlayfs copy-up under the mounter's is not. The owner purges a stale record and probes that `cred_free` runs (it needs an active LSM with a cred blob: SELinux, AppArmor, Landlock). Include it after `bindings.h` and `arming.h` |
| `pin.h` | the section's state maps are pinned by name with its prefix (`SANDBOX_SECTION`, for example `sbx1_priv_`): a new load of the gadget re-opens them, so a restart keeps bindings, slot state, policy, task marks and fault counts. `enforcement.RemovePinnedMaps` starts from empty state |
| `merge/` | the merge contract for several policies on one container, and its shared test vectors |
| `rootbarrier/` | Go: attestation (each barrier program has a live LSM link, BPF LSM is active) and a self-test, for the Ready step of a gadget that includes `root_barrier.h` |
| `enforcement/` | Go: the binding controller of one long-lived node-wide instance: live `Bind`/`Unbind` of a container to a slot; `Rebind` hands a bound cgroup to another identity with one map write; `ReadEntry` reads a cgroup's kernel entry back and `EntryOf` is the entry a bind writes (both without the io_uring check flag); `Publish` of a slot's policy into its inactive buffer and one flip write (a failed publish keeps the last-good policy); `Free` and a quarantine (default 2 s) before a buffer is deleted or a slot reused; `Heal`/`HealNode` arm the bound tasks again without a reload; readiness, `SlotFaults`, `ArmingWitness` (a counter below its base or unreadable is an error, never zero); `Counters`/`NodeCounters` read the raw pinned counters, and `RateWindow`/`FailRate` (failrate.go) apply the reporting rule: Degraded on any failure within 60 s, NotReady above 0.1 % over 5 min, unknown when a counter is unreadable or moved backwards. A section instance with a test-only switch set is refused unless `FaultInjection` admits it. A frozen mode (policy written and frozen before any binding) stays for sections not moved yet |

Section-specific parts (the policy key layout, hooks, compiler) stay in each
gadget.

## Build

`ig image build` mounts only the gadget folder, so `#include "../common/..."`
does not resolve by default. A gadget Makefile sets `IG_SOURCE_PATH` to the
repository root; the builder then mounts the whole repository. This reuses an
Inspektor Gadget variable meant for in-tree gadgets of the Inspektor Gadget
repository.
