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
func ResolveEventTime(enrichedEvent *events.EnrichedEvent) time.Time {
	if enrichedEvent == nil {
		return time.Time{}
	}
	if enrichedEvent.Event != nil {
		if ns := int64(enrichedEvent.Event.GetTimestamp()); ns > 0 {
			return time.Unix(0, ns)
		}
	}
	return enrichedEvent.Timestamp
}
