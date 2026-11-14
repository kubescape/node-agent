# Third-party event types

A tracer added through `GetThirdPartyTracers` can emit its own event type (for
example `memfd`) and register receivers for it on the third-party receiver map:

```go
receivers.Set(MemfdEventType, mapset.NewSet[containerwatcher.GenericEventReceiver](ruleManager, metrics))
```

`EventHandlerFactory.ProcessEvent` delivers every event in two passes:

1. **Built-in handlers** for the event type (container profile manager, rule
   manager, DNS manager, network stream, ...). A custom type has none, so this
   pass does nothing for it.
2. **Third-party receivers** registered for the event type, which is where a
   custom type's events go.

An event type with no built-in handlers still reaches pass 2. Before this, it
returned before pass 2, so custom event types never reached their receivers and
rules on them never fired.

The usual gates still apply before both passes: events without a container ID,
events from an unknown or ignored container, and unsolicited ingress are
dropped. Rule-only events (forwarded DNS queries) still never reach third-party
receivers (see [dns-query-rule-forwarding.md](dns-query-rule-forwarding.md)).
