# Exec argv boundaries

`event.args` keeps the argument boundaries of the captured argv: one element
per argument, with its content unchanged, even when an argument contains the
separator character. A process cannot merge or split arguments through the
encoding.

The capture itself has limits that this does not change: `decodeExecArgs`
drops a trailing argument cut by the capture limit (keeping a truncated
argv[0]), and an argv of exactly one empty argument (`[""]`) reads back as nil,
the same as "argv not captured". Rules that rely on `size()` should keep that
in mind.

## Why the encoding exists

The exec datasource has no array type, so the exec operator
(`pkg/containerwatcher/v2/tracers/execoperator.go`) packs argv into the single
string field `args`, separated by U+00A0 (`igconsts.ArgsSeparator`).
`DatasourceEvent.GetArgs()` splits it again.

A plain join cannot carry an argument that itself contains U+00A0: before this
fix such an argument came back as several arguments. A process controls its own
argv, so it could make `event.args` differ from the real argv in both count and
content, for example to match a rule exclusion that pins every element
(SUB-9501, R1135 docker-clean apt-hook exclusion).

## Encoding

`utils.JoinExecArgs` escapes each argument before the join, and
`utils.SplitExecArgs` reverses it after the split:

| In an argument | In the `args` field |
|---|---|
| `\` | `\\` |
| U+00A0 | `\u00a0` (six characters) |

After the escaping, a raw U+00A0 in the field is always a separator. Arguments
without a backslash or U+00A0 are encoded unchanged.

An empty field still means "argv not captured": `GetArgs()` returns nil.

## Who sees what

- Rules (CEL `event.args`), profiles, the process tree and alerts read argv
  through `GetArgs()` and get the original arguments.
- Anything that reads the raw `args` datasource string directly sees the escaped
  form. Inside node-agent, only `GetArgs()` does.
- `StructEvent` (procfs and tests) carries `Args []string` and does not use the
  encoding.

## Rule authors

No rule change is needed. Agents built before this change still split
arguments that contain U+00A0, so a rule that depends on argument boundaries for
an exclusion should keep that caveat until those agents are gone.

## Code

- `pkg/utils/exec_args.go`: `JoinExecArgs`, `SplitExecArgs`.
- `pkg/containerwatcher/v2/tracers/execoperator.go`: join on the producer side.
- `pkg/utils/datasource_event.go`: `GetArgs()` on the consumer side.
- `pkg/utils/exec_args_test.go`: round trips, the forged-argv case, and
  `GetArgs()` on a synthetic exec datasource.
