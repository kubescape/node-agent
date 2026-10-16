# Exec controlling-terminal (TTY) fields

Four CEL fields on exec events describe the process's controlling terminal:

| Field | Type | Meaning |
|---|---|---|
| `event.hasTty` | bool | **Use this one.** True when the process has a controlling terminal. |
| `event.ttyMajor` | uint | Terminal driver major: `136` = pseudo terminal (`kubectl exec`, `docker exec`, ssh), `4` = virtual console, `0` = none. |
| `event.ttyMinor` | uint | Terminal device minor. |
| `event.tty` | int | Raw driver-local index. **Does not uniquely identify a device** — the index is only unique per driver, so `/dev/pts/0` and `/dev/tty0` are both `0`. A nonzero value does mean a terminal is present; only `0` is ambiguous, meaning either `/dev/pts/0` or no terminal at all. Prefer `ttyMajor`. |

## Not every agent measures this

The bundled `trace_exec:v0.48.1-tty` is built from v0.48.1 with upstream
commit `c6fc831a` backported for terminal device numbers. It preserves the
execve pathname in `args[0]`, keeping existing profile argument matching
and executable-path consumers compatible.

`ttyMajor`/`ttyMinor` require a gadget version that emits the terminal device
number. Agents bundling an older `trace_exec` gadget may leave those fields
absent, and `has()` reports that capability:

```cel
has(event.ttyMajor)   // false when this agent cannot measure the device number
```

`has(event.hasTty)` is true on any agent with a working exec tracer.

## Two authoring rules

**Positive predicates need no guard and no version gate.** Safe on every agent
version; on older agents they under-fire rather than mis-fire:

```cel
event.hasTty && event.comm in ["bash", "sh", "zsh"]
```

**Negative predicates require a version gate.** On agents without the device
number, `hasTty` is derived from the ambiguous index, where `0` is read as "no
terminal" — which is wrong for `/dev/pts/0`, the usual first `kubectl exec`
into a pod. A rule asserting "not interactive" would fire on genuinely
interactive shells. Such a rule must carry an `agentVersionRequirement` for
the minimum node-agent release in the target fleet; do not infer or guess that
release from the gadget version alone:

```yaml
- name: "Non-interactive download tool"
  expressions:
    ruleExpression:
      - eventType: exec
        expression: |
          !event.hasTty &&
          event.exepath in ["/usr/bin/curl", "/usr/bin/wget"]
  agentVersionRequirement: ">=<minimum node-agent release in your fleet>"
```

## Comparing the numeric fields

`ttyMajor` and `ttyMinor` are unsigned; this CEL environment has no
cross-type numeric comparison, so comparing against a bare integer literal
fails to compile (and thus silently disables the rule) rather than failing
at runtime. Compare them with an explicit unsigned literal:

```cel
has(event.ttyMajor) && event.ttyMajor == uint(136)
```

`event.tty` is signed, so it takes a bare integer instead: `event.tty == 3`.

## Cluster validation

`tests/component_test.go:Test_35_ExecTTYFieldTest` proves the fields work
end-to-end against real eBPF, using four test-only rules in
`tests/resources/exec-tty-rules.yaml`. With `trace_exec:v0.48.1-tty`, the expected
results on kind are:

```
R9901 (hasTty)   c-none=0  c-pts0>0  c-conc>0
R9902 (control)  total=3
R9903 (has field) c-none>0  c-pts0>0  c-conc>0
R9904 (absent)   total=0
```

Three properties the test pins down, each for a reason:

- **The control rule matters.** An unresolvable CEL field does not raise an
  error — it fails to compile and silently disables the whole expression. "No
  alert" is therefore ambiguous between "the field was false" and "the rule
  never ran". R9902 shares the trigger without the TTY predicate, so it
  separates the two. Verified by mutation: pointing R9901 at a nonexistent
  field drops it to 0 while R9902 stays at 3.
- **R9903/R9904 prove field presence.** R9903 must fire for all three events,
  including the no-TTY event whose `tty_major` value is zero. R9904 must stay
  silent. Both silent would mean `ttyMajor` is unregistered rather than
  absent, while R9903 firing confirms `has()` sees the emitted field.
- **`c-pts0` must fire.** A single exec into a fresh container lands on
  `/dev/pts/0`; the backported gadget reports its nonzero terminal major even
  though the raw `tty` index is zero. This covers the bug reported in #975.
  The concurrent trigger still exercises a nonzero index so both
  representations remain covered.

Two environment facts the test depends on, both verified rather than assumed:

- Containers in a pod have separate mount namespaces and therefore separate
  `/dev/pts` instances, so each of the three containers starts from a pristine
  pts index. With a session held in one container, an exec into a sibling still
  lands on `/dev/pts/0`.
- The API server allocates a pty on `PodExecOptions.TTY` alone, regardless of
  `Stdin` — so ordinary component-test execs already carry a terminal, and
  `ExecIntoPodNoTTY` is what a test needs for a terminal-free process.
  `kubectl exec -t` is not a way to check this: kubectl silently drops the TTY
  flag when `-i` is absent and misleadingly reports "not a tty".

Because pts indices are not reclaimed instantly, the concurrent trigger waits
for the holder to *report* its own tty path rather than launching it and
sleeping. This makes the nonzero-index coverage deterministic.

See `projects/2026-07-27-exec-tty-cel-field/spec.md` in shared-designs-and-docs
for the full design and the test rationale.
