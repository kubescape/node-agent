# Exec controlling-terminal (TTY) fields

Four CEL fields on exec events describe the process's controlling terminal:

| Field | Type | Meaning |
|---|---|---|
| `event.hasTty` | bool | **Use this one.** True when the process has a controlling terminal. |
| `event.ttyMajor` | uint | Terminal driver major: `136` = pseudo terminal (`kubectl exec`, `docker exec`, ssh), `4` = virtual console, `0` = none. |
| `event.ttyMinor` | uint | Terminal device minor. |
| `event.tty` | int | Raw driver-local index. **Does not identify a terminal** — the index is only unique per driver, so `/dev/pts/0` and `/dev/tty0` are both `0`. Prefer `ttyMajor`. |

## Not every agent measures this

`ttyMajor`/`ttyMinor` require a gadget version that emits the terminal device
number. On older agents those fields are absent, and `has()` reports it:

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
interactive shells. Such a rule must carry an `agentVersionRequirement`:

```yaml
- name: "Non-interactive download tool"
  expressions:
    rule_expression:
      - event_type: exec
        expression: |
          has(event.hasTty) && !event.hasTty &&
          event.exepath in ["/usr/bin/curl", "/usr/bin/wget"]
  agentVersionRequirement: ">=<version that ships the device number>"
```

See `projects/2026-07-27-exec-tty-cel-field/spec.md` in shared-designs-and-docs
for the full design and the phase-2 checklist.
