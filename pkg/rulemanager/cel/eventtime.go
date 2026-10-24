package cel

import (
	"time"

	"github.com/kubescape/node-agent/pkg/ebpf/events"
)

// ResolveEventTime returns the single authoritative timestamp for an event.
//
// It prefers the event's own kernel timestamp, because ordering guards must
// compare when things HAPPENED, not when node-agent got around to seeing them --
// events are processed by a concurrent worker pool, so observation order is not
// causal order. Some events report a zero timestamp; those fall back to the
// enrichment time rather than the epoch.
//
// Both the CEL "timestamp" variable and rulestate.Entry.Timestamp are populated
// from this function. They must never diverge: a mismatch would make the _ts
// join compare different clocks and silently never fire.
//
// The event clock must be a WALL clock, because ExpiresAt is derived from it
// while expiry is checked against time.Now(). Every producer today satisfies
// that -- DatasourceEvent.GetTimestamp goes through gadgets.WallTimeFromBootTime,
// and procfs and syscall events use time.Now().UnixNano() directly -- but that is
// a property of the current producers, not something the type system enforces. A
// future source handing over a raw boot-time value would yield 1970-plus-uptime,
// every entry from that stream would be born expired, and the rule would silently
// never fire. So the invariant is checked rather than assumed: a timestamp
// implausibly far from now is discarded in favour of the enrichment time.
//
// The window is deliberately wide. It exists to catch a wrong EPOCH -- off by
// decades -- not clock skew, and it must never reject a legitimately late or
// slightly-ahead event.
const maxEventTimeSkew = 24 * time.Hour

func ResolveEventTime(enrichedEvent *events.EnrichedEvent) time.Time {
	if enrichedEvent == nil {
		return time.Time{}
	}
	if enrichedEvent.Event != nil {
		if ns := int64(enrichedEvent.Event.GetTimestamp()); ns > 0 {
			if t := time.Unix(0, ns); plausibleEventTime(t, time.Now()) {
				return t
			}
		}
	}
	return enrichedEvent.Timestamp
}

// plausibleEventTime reports whether t could be a wall-clock reading of now.
func plausibleEventTime(t, now time.Time) bool {
	d := now.Sub(t)
	if d < 0 {
		d = -d
	}
	return d <= maxEventTimeSkew
}
