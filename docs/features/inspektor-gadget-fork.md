# inspektor-gadget fork

node-agent depends on a fork of `inspektor-gadget/inspektor-gadget` via a `replace`
directive in `go.mod`, instead of the upstream module, because node-agent needs
changes (e.g. eBPF map manual-fetch triggers, syscall map handling) before they land
upstream.

## Current fork

The long-term fork is **`github.com/kubescape/inspektor-gadget`**, pinned to a specific
commit via a pseudo-version:

```
replace github.com/inspektor-gadget/inspektor-gadget => github.com/kubescape/inspektor-gadget v0.0.0-<timestamp>-<short-sha>
```

This is an org-owned fork of `inspektor-gadget/inspektor-gadget`, kept as a plain
mirror of whatever commit node-agent currently needs — it is not meant to diverge
with its own history. Previously this pointed at a personal fork
(`matthyx/inspektor-gadget`); that was migrated to the org fork so the dependency
isn't tied to one contributor's personal account.

### Temporary pin: IG v0.57.0 merge (fork PR #17)

The IG v0.57.0 merge (fork PR #17, commit `ddcb1a5766427456dac3a2b9bd7bcac7cc5f0868`)
is not on `kubescape/inspektor-gadget:main` yet, so the commit does not resolve
under the `kubescape` module path. Until #17 merges, `go.mod` pins the
contributor's fork, which carries the same commit:

```
replace github.com/inspektor-gadget/inspektor-gadget => github.com/ANAMASGARD/inspektor-gadget v0.0.0-20261027113509-ddcb1a576642
```

After #17 merges, re-pin to the merged commit on `kubescape/inspektor-gadget`
(see "Updating the pin"). The `NOTE:` comment above the replace line makes
`make check-ig-pin` fail until then; the guard's ancestor check only covers the
`kubescape` path, so the marker is what blocks a merge. Remove it when re-pinning.

### Carried replaces

`replace` directives in a dependency's `go.mod` do not apply to consumers, so
node-agent copies the ones the fork needs from the fork's `go.mod`:

```
replace github.com/notaryproject/notation-go => github.com/inspektor-gadget/notation-go v1.3.3
replace go.opentelemetry.io/ebpf-profiler => github.com/inspektor-gadget/opentelemetry-ebpf-profiler v0.0.202611-0.20260715114040-ef6cf29492c8
```

Keep them in sync with the fork's `go.mod` whenever the pin moves. The v0.57.0
fork also requires the k8s.io v0.37 modules (`k8s.io/kubectl` v0.37.1).

### Gadget images

The upstream gadgets (`trace_exec`, `trace_capabilities`, `trace_dns`,
`advise_seccomp`) are pulled unmodified at `v0.57.0` (`Makefile` `VERSION`).
The `trace_capabilities` 10240 change that used to need the fork is upstream in
v0.57.0. `trace_open` is vendored under `pkg/ebpf/gadgets/trace_open` (upstream
v0.57.0 plus the local dirfd path-resolution patch) and built with the v0.57.0
gadget builder.

## Exec event semantics (IG v0.57)

Since IG v0.57, `trace_exec` captures argv after the exec, so `args` is the real
argv, including the real `argv[0]` (`sh`, not `/bin/sh`). node-agent reads three
exec fields:

| Field | Meaning |
|---|---|
| `file` | The file the kernel executed (`d_path(bprm->file)`), with symlinks resolved. For a shebang script, it is the script. Exposed as `GetFile()`. |
| `exepath` | The process's executable (`/proc/<pid>/exe`). For a shebang script, it is the interpreter. For binfmt_misc, it is the emulator. |
| `args` | The real argv. When argv cannot be read, the event is kept and `GetArgs()` returns `nil`. |

### Exec path

`GetExecPathFromEvent` returns `file`, then `exepath`, then `comm`. It never uses
`argv[0]`, because the caller controls `argv[0]` and can spoof it. Profiles are
recorded by `exepath`, so profiles learned before the upgrade raise no new R0001
anomalies.

Accepted consequence: glibc `system()` reports `/usr/bin/dash` (Debian, Ubuntu) or
`/bin/busybox` (Alpine), not `/bin/sh`.

Alerts:

- The `exec` argument is the exec path.
- `CommandLine` and `Cmdline` are the full argv joined by spaces, so a busybox
  applet name is kept. They fall back to the exec path when argv is empty.
- The `File` entity is `exepath` when it is set, otherwise the exec path.

### R0040 argument matching (B1′)

`cp.was_executed_with_args` matches the runtime argv against each argv vector the
profile recorded for the path:

- An empty profile vector means "no constraint" and matches anything.
- An empty or `nil` runtime argv is an unknown capture, not "ran with no
  arguments". It matches, so R0040 does not fire. R0001 still covers the path.
- If profile `argv[0]` contains `⋯`, the full vectors are compared.
- Otherwise `argv[0]` is compared by basename, ignoring one leading `-`. A
  profile `["/bin/sh","-c","x"]` matches `["sh","-c","x"]`, and `-bash` matches
  `/bin/bash`. Busybox applets stay distinct: `ls` does not match `cat`. The rest
  of the vectors is compared with the storage matcher.
- A one-element profile requires a one-element runtime argv: `["/usr/bin/cat"]`
  does not match `["cat","x"]`.
- `⋯` matches one argument (or one path segment inside an argument), `⋯⋯` matches
  zero or more arguments, and `*` is always literal.

Accepted consequences, until the profile is relearned:

- A shebang profile learned before the upgrade (`[script, …]`) does not match the
  new argv (`[interpreter, script, …]`), so R0040 fires.
- The legacy gadget captured at most 20 arguments of at most 255 bytes each. A
  profile learned with a truncated argument, or with more than 20 arguments,
  does not match the full argv, so R0040 fires. There is no prefix tolerance.
- `exec -a name` renames `argv[0]`, so R0040 fires. This is intended.
- Profiles that are still learning during the rollout can record the same exec
  twice, with the old and the new argv, as two hash entries.

### Malware scan paths

For an exec event, the malware manager scans:

- `file` under the container root (`/proc/<container-pid>/root/<file>`);
- `/proc/<pid>/exe` instead when `file` is empty, starts with `/memfd:`, or ends
  with ` (deleted)`, because no reachable path exists. If the pid is unknown, the
  path is skipped and a debug message is logged;
- `exepath` as well when it differs from `file` (a shebang script or a
  binfmt_misc binary), with the same fallback.

Open events are scanned by their full path, as before.

### Rule gating

Rules that need the exepath-first form are gated with
`agentVersionRequirement: ">=0.3.111"` (private-node-agent `>=0.0.264`). Agents
older than these versions do not load the gated rules.
