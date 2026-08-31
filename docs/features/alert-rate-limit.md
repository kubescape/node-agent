# Alert Rate Limit

`maxAlertsPerMinute` (in `httpExporterConfig`, default `100` via `Validate()`) bounds how many
alerts the HTTP exporter sends to the backend in a one-minute window. Past the bound the
exporter drops alerts and sends a single `AlertLimitReached` alert to say so.

## How it works

`admitAlert` is called once per send, on both `SendRuleAlert` and `SendMalwareAlert`. It holds
the exporter's mutex for the whole decision and returns two values:

| | Meaning |
|---|---|
| `admitted` | the alert may be sent. False for **every** alert past the limit in the window. |
| `notify` | send the `AlertLimitReached` alert. True only for the **first** refusal in the window. |

The window is lazy: the first call, and any call more than a minute after the window started,
resets the counter and starts a new window. A limit of zero or less means no limit — `Validate()`
already replaces a zero with the default, so that only guards an exporter built by hand.

Every refused alert is counted in `ReportAlertSuppressed(<rule id>, "rate_limit")`.

## Why two return values

The previous implementation returned one boolean, `count > max && !isNotified`, which combined
both decisions. The first alert past the limit was dropped and set `isNotified`, and that made
the condition false for every later alert in the same minute — so they were all sent. The
limiter dropped exactly one alert per minute and let the rest through, which in practice is no
limit at all.

Two smaller consequences of the same rewrite:

- The old code reset the window with an early `return false` **without counting** the alert that
  triggered the reset, so the effective limit was `max + 1`.
- `ReportAlertSuppressed` fired once per minute rather than once per dropped alert, so the
  suppression metric could not measure the loss.

## What it does not do

The limit is a fixed window, not a sliding one, so a burst at a window boundary can send up to
`2 × max` in a short span. That is inherent to the design and unchanged.

The limit is per exporter instance. Consumers that share one exporter share one budget.
