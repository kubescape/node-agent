# CEL rule state store

Gives a CEL rule memory across events, so a detection can span more than one
event: remember something on `exec`, alert on `network`. Without it, every rule
is a pure predicate over a single event and multi-step behaviour — a process
launched from a mount that later connects out, a webshell chain, create/exec/
delete of a pod — cannot be expressed at all.

Design: `shared-designs-and-docs/projects/2026-07-28-cel-rule-state-store/spec.md`.

> **Status: under construction.** This page documents what has landed. The read
> functions below exist and are tested, but nothing populates the store yet —
> writes (`stateWrites:`) are still to come, so in a running agent every read is
> currently a miss.

## Reading state

Four functions, on a `state` receiver:

```cel
state.has(name)                  // bool  — for a fact about the whole scope
state.has(name, key)             // bool  — for a fact about one subject
state.get(name)                  // map   — empty map on a miss, never an error
state.get(name, key)             // map
state.has_ancestor(name)         // bool  — any ancestor PID carries the marker
state.get_ancestor(name)         // map   — the NEAREST matching ancestor
```

`name` is what kind of fact ("mount_exec"); `key` is who it is about, usually
`string(event.pid)`. A read takes **no scope argument**: state is rule-private,
so the name already determines its scope from the rule's own `stateWrites`.

`state.get` on a miss returns an **empty map**, so guard provenance access with
`state.has` — `state.get("x", k)._pid` on a miss is a "no such key" error, and
that error fails the whole predicate:

```cel
state.has("mount_exec", string(event.ppid)) &&
  state.get("mount_exec", string(event.ppid))._ts < timestamp
```

### What `state.get` returns

Engine-stamped provenance uses reserved `_`-prefixed keys; the rule's own
`value:` entries sit alongside them at the top level. Author keys may not begin
with `_`, so they can never shadow provenance.

| Key | Type | Meaning |
|---|---|---|
| `_ts` | timestamp | When the remembered event happened. Compare against `timestamp`. |
| `_eventType` | string | The event stream that wrote the entry. |
| `_container` | string | The scope ID the entry lives under. |
| `_pid` / `_ppid` | uint | Process and parent PID. |
| `_comm` / `_pcomm` | string | Process and parent command name. |
| `_exe` | string | Executable path. |
| `_cwd` | string | Working directory. |

### The ancestor functions assume a PID key

`has_ancestor` / `get_ancestor` probe each ancestor PID in turn, so they only
find entries whose `key` was a PID. That is an authoring contract, not something
the engine can check — write `key: string(event.pid)` for any name you intend to
read this way.

They work identically for host and containerised processes.

### Why `state` is a variable, not a function namespace

Unlike `process.*` or `net.*`, `state` is a **variable** with member functions.
cel-go hands a function binding only its arguments, never the surrounding
context, so a global `state.has` could not know which rule or which container it
was evaluating for.

That is also the security property: the rule ID, the scope IDs and the ancestor
list live in the receiver, and no CEL syntax supplies or overrides them. Reading
another rule's state or a neighbouring container's state is not merely forbidden
— it is inexpressible.

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
