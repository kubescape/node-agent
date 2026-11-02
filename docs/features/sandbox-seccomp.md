# SandboxPolicy seccomp layer (experimental)

Enforces the syscall rules of a SandboxPolicy `privilege` section with seccomp.
It is independent of the exec enforcement in `sandbox-policy.md`: it needs no BPF
LSM, and it runs with or without `sandboxPolicyEnabled`.

## Configuration

Disabled by default:

```json
{"sandboxSeccompEnabled": false, "sandboxSeccompNRISocket": "/var/run/nri/nri.sock"}
```

The agent needs the NRI socket mounted at that path, write access to the
kubelet seccomp directory (the existing `HOST_ROOT`/`KUBELET_ROOT` mount used by
the seccomp manager), and get/list on pods, namespaces, nodes, SandboxPolicy and
ClusterSandboxPolicy, plus SandboxPolicyNodeStatus writes. A start-up failure is
logged and disables only this layer.

## What it compiles

Only rules whose target is `syscall` (with optional `flags`). Capability,
`mountFsType` and `pathClass` targets belong to other hooks and are reported, not
dropped. Every other rule shape seccomp cannot express is reported the same way:
actor predicates, `flags` on `setns` (nstype 0 joins any namespace), and `clone`
without flags (it would deny every process creation).

- A CRD syscall name expands to its whole kernel family: `mount` also denies
  `fsopen`, `fsconfig`, `fsmount`, `fspick`, `move_mount`, `open_tree` and
  `mount_setattr`; `setuid` also denies `setreuid`, `setresuid` and `setfsuid`;
  `keyctl`, `kexec_load`, `mknod` and `setgid` likewise.
- `flags` on `clone`/`unshare` become one masked-equal match per namespace bit.
- `clone3` passes its flags in memory, out of seccomp's reach. When `clone` has
  an enforced flag rule, `clone3` is denied with `ENOSYS`, so glibc falls back to
  `clone` where the flag rule applies. `EPERM` would make glibc fail every new
  thread ("can't start new thread"); this was reproduced with glibc 2.41.
- `enforce` → `SCMP_ACT_ERRNO` (`EPERM`) and `SECCOMP_FILTER_FLAG_LOG`;
  `audit` → `SCMP_ACT_LOG`. Across policies, deny wins and enforce wins over audit.
- A section `default: deny` denies the CRD syscall vocabulary, except syscalls
  with an allow rule. For `clone`/`unshare` it means "with any namespace flag". A
  syscall with an actor- or flag-scoped allow is not denied by seccomp: seccomp
  cannot scope the exception, so another layer must.
- When the exec controller runs, a pod with an enforced exec policy also gets the
  root barrier exec enforcement relies on (`chroot`, `pivot_root`, `setns`,
  `unshare`, `clone3`, and the `CLONE_NEWUSER`/`CLONE_NEWNS` bits of `clone`),
  reported as rule `exec-root-barrier`. Audit policies do not get it.

## Base profile

SandboxPolicy only adds denials to the profile the container would run anyway:

- The runtime's report wins. containerd reports the profile kind to NRI and, for
  RuntimeDefault, the exact profile (verified on containerd 2.3.4). That exact
  profile is the base, with denied syscalls removed from its allow entries and
  flag denials narrowing them. Audited syscalls the base allows are logged,
  never silently allowed; syscalls the base already denies stay denied.
- `Unconfined`: default allow plus the denials. Native and compat ABIs are both
  listed (x86_64/x86/x32, aarch64/arm), so 32-bit binaries are filtered, not
  killed; `setuid` and `setgid` include their `*32` variants.
- Without a runtime report and without a profile in the pod spec, the kubelet
  may still apply RuntimeDefault (`seccompDefault`). The layer does not inject
  then, and reports the container. Fallback files for such pods are built on
  RuntimeDefault, the stricter choice.
- A container's own `Localhost` profile and privileged containers are left
  alone and reported.

## Delivery

1. **NRI (preferred).** The layer registers as NRI plugin `50-kubescape-sandbox`
   and sets the profile in `CreateContainer`. It also adds the annotation
   `kubescape.io/sandbox-seccomp` with the profile revision, which the runtime
   keeps, so a restarted agent knows which containers already run which profile.
   Seccomp adjustment needs containerd ≥ 2.2.0 or CRI-O ≥ 1.34.0 with NRI enabled
   (the default since containerd 2.0). An older runtime may accept the adjustment
   and drop the profile, so the plugin checks the runtime version at registration
   and stays on fallback files otherwise. The layer never fails container
   creation: a container it cannot protect is reported instead. The creation hook
   reads caches, with lookups bounded well under NRI's 2 s request timeout.
2. **Fallback file.** Without NRI, the profile is written to
   `<kubelet>/seccomp/kubescape-sandbox/<base>-<revision>.json` (`rd-` or `uc-`). The
   layer never changes a pod spec; a pod opts in by setting
   `seccompProfile: {type: Localhost, localhostProfile: kubescape-sandbox/<file>}`.
   Files no pod uses are removed after 10 minutes.

## Applies on restart

The kernel cannot remove or loosen a seccomp filter of a running process, so a
profile reaches a container only when it is created. Every 5 s, and on policy
watch events, the layer compares each container's injected revision with the
desired one. Policies are listed after a watch event and every minute; without
NRI, the node's pods are listed every 30 s. Rules of containers that differ are listed in the policy's node
report under `status.appliesOnRestart`, with the reasons in the
`SeccompAppliesOnRestart` condition, for example "2 container(s): policy changed
after the container started". Rules seccomp cannot express are listed in the
`SeccompRulesNotEnforced` condition. With exec enforcement enabled, these are
added to the exec controller's report; otherwise the layer writes the report
itself with tier `seccomp-only`. Either way, Ready is False while any rule waits
for a restart or is not enforced. With the layer disabled, a policy with a `privilege`
section reports `PrivilegeNotEnforced` and is not Ready. A restart button in the UI is a possible
follow-up; the operator's `operatorAction` framework could carry it.

## Events

The `audit_seccomp` IG gadget (added to `tracers.tar`, enabled with this layer)
reports the kernel's seccomp log records. The layer keeps only records of
profiles it injected, drops runc's own `open_tree` records (runc retries a denied
`open_tree` with the old mount API during `kubectl exec`), attributes the syscall to the policy
rules, and dispatches a `seccomp.Verdict` to receivers registered under
`utils.SyscallAuthorizationEventType` (`syscallAuthorization`), either as
`seccomp.VerdictReceiver` or as `EventReceiver`. Like `execAuthorization`, this is
an authorization record, not a syscall observation.

Attribution uses the rules of the revision injected into that container and
needs no API calls. `SECCOMP_FILTER_FLAG_LOG` logs every ERRNO decision of the
profile, including the base's own denials and the `clone3` `ENOSYS` that glibc
hits on each new thread; those records are dropped here, but the kernel still
writes them. The volume on thread-heavy workloads is not measured yet.

The kernel record carries no arguments. A match on a flag rule is therefore a
candidate, marked `MatchesComplete=false`. The wire name of the exported event
is proposed in the private exporter, not here.

## Verification

Unit tests cover compilation, profile merging on both bases, pending reasons,
fallback files and event attribution. A lab run on kind (Kubernetes 1.36,
containerd 2.3.4, arm64, kernel 6.8) confirmed: NRI injection into a selected
pod only; `unshare -U` and `mount` denied with `EPERM` in enforce and logged in
audit; threads still working; `kubectl exec` still working; the RuntimeDefault
merge keeping the runtime's own default-deny profile; compat ABIs and syscall
names unknown on arm64 accepted by runc; pending reasons after a policy change and after a
layer restart (revisions recovered from the annotation); and the fallback file
protecting an opted-in pod. The `audit_seccomp` tracer path inside a full
node-agent deployment was not run in the lab.
