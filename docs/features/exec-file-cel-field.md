# Exec `file` CEL field

`event.file` is the file the kernel executed: `d_path(bprm->file)`, emitted by
`trace_exec` since Inspektor Gadget v0.57.0. It is symlink-resolved, like
`event.exepath`, but the two differ when the executed file is not the binary
that ends up running:

| Exec | `event.file` | `event.exepath` | `event.args[0]` |
|---|---|---|---|
| ELF binary `/bin/ls` | `/usr/bin/ls` | `/usr/bin/ls` | `ls` |
| Shebang script `/run/x.pid` (`#!/bin/sh`) | `/run/x.pid` | `/usr/bin/dash` | `/bin/sh` |
| binfmt_misc (e.g. a `.jar` handler) | the registered file | the interpreter | as passed |

Use `event.file` when a rule must match the executed file itself, for example a
script under a runtime-state directory. Keep `event.exepath` for profile
lookups: profiles store `exepath`, and `GetExecPathFromEvent` resolves the
alert path as file, then exepath, then comm.

## Presence and fallback

`has(event.file)` is true when the running gadget emits the field. It can still
be empty when the kernel path could not be resolved, so rules use a fallback:

```cel
(event.file != "" ? event.file : event.exepath)
```

`StructEvent` (ptrace and tests) reports `file` present when it is non-empty.

## Version gate

An agent built before this field existed does not register `event.file`, so a
rule that references it fails to compile there and is skipped. Gate such rules
with `agentVersionRequirement` set to the first release that carries this
change (kubescape/node-agent, and for private agents the first
private-node-agent release that pins it). The rules watcher skips a rule whose
requirement the agent does not meet before compiling it.

## Code

- `pkg/utils/cel.go`: the `file` entry in `CelFields`, `IsSet: presenceOf("file")`.
- `pkg/utils/struct_event.go`: `FieldPresent("file")`.
- `pkg/rulemanager/cel/cel_file_test.go`: shebang, missing-field and fallback cases
  against both `StructEvent` and a synthetic exec datasource.
