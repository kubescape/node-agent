# CEL rule state store

Gives a CEL rule memory across events, so a detection can span more than one
event: remember something on `exec`, alert on `network`. Without it, every rule
is a pure predicate over a single event and multi-step behaviour — a process
launched from a mount that later connects out, a webshell chain, create/exec/
delete of a pod — cannot be expressed at all.

Design: `shared-designs-and-docs/projects/2026-07-28-cel-rule-state-store/spec.md`.

> **Status: under construction.** This page documents what has landed. Sections
> appear as the implementation does; the state read/write surface itself is not
> usable yet.

## `timestamp` — the resolved event time

A top-level CEL variable (not an `event` field) holding the authoritative time
for the event being evaluated:

```cel
timestamp                          // a CEL timestamp
timestamp - duration("5m")         // arithmetic and comparison work
```

It is the event's **kernel** timestamp where the event carries one, falling back
to node-agent's enrichment time only when that is zero.

Two reasons it is defined this way:

**Kernel time, not observation time.** Events are processed by a concurrent
worker pool, so the order node-agent *sees* events is not the order they
*happened*. Any ordering comparison has to be against when things happened or it
is meaningless.

**One source of truth.** The same function populates both this variable and the
timestamp stamped onto stored state entries. If the two could disagree, an
ordering guard would be comparing different clocks and would silently never
fire — the worst failure mode for a detection rule.

It is a top-level variable rather than `event.timestamp` because the `event`
field getters receive a wrapper around the raw event and cannot see
node-agent's enrichment time; an event field would therefore have to be a
second, divergent source of truth.

### Timezone

`string(timestamp)` renders in the node's local zone, so the offset in the text
depends on where the agent runs. Comparisons are instant-based and unaffected.
Assert on instants, not on rendered text.
