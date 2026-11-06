# `net.format_endpoint`: IPv6-safe `addr:port` in rule messages

`event.dstAddr` on network events can be an IPv6 address (since #1033).
Building an endpoint as `event.dstAddr + ':' + string(event.dstPort)` is
ambiguous for IPv6: `fd00::1` on port `23` prints as `fd00::1:23`, which is
itself a valid address.

`net.format_endpoint(addr, port)` returns the standard form:

| Call | Result |
|---|---|
| `net.format_endpoint('10.0.0.5', 23)` | `10.0.0.5:23` |
| `net.format_endpoint('fd00::1', 23)` | `[fd00::1]:23` |
| `net.format_endpoint('fe80::1%eth0', 22)` | `[fe80::1%eth0]:22` |

Signature: `net.format_endpoint(string, int) -> string`. `event.dstPort` is a
CEL `int`, so it passes directly:

```cel
'Connection to ' + net.format_endpoint(event.dstAddr, event.dstPort)
```

It uses Go's `net.JoinHostPort`: any address containing `:` is bracketed,
anything else (IPv4, a hostname, an empty string) is left as is. The address is
not validated or resolved. Use it for message text only; it does not change
detection.

## Agent version

Agents without this function fail to compile any expression that calls it. A
rule that adopts it must carry an `agentVersionRequirement` for the first agent
version that ships it.
