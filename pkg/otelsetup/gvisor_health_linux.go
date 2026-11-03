//go:build linux

package otelsetup

import (
	"context"
	"time"

	"github.com/kubescape/node-agent/pkg/gvisor"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
)

// EmitGVisorHealth submits a bounded, payload-free diagnostic record through
// the existing log provider. A disconnected trace sender is not a stopped
// container. ExportSubmitted counts handoff to OTEL, not remote receipt.
func EmitGVisorHealth(ctx context.Context, h gvisor.Health) {
	state := "stopped"
	if h.Running {
		state = "retrying_listener"
		if h.Receiver.Listening {
			state = "listening"
			if h.Receiver.ActiveConnections > 0 {
				state = "connected"
			}
		}
	}
	var r otellog.Record
	now := time.Now()
	r.SetTimestamp(now)
	r.SetObservedTimestamp(now)
	r.SetSeverity(otellog.SeverityInfo)
	r.SetBody(attribute.StringValue("RuntimeSourceHealth"))
	r.AddAttributes(attribute.String("source", "gvisor_trace"), attribute.String("state", state),
		attribute.Int64("active_connections", h.Receiver.ActiveConnections))
	// Fixed keys only: never use IDs, raw error text or frame contents as fields.
	counts := map[string]uint64{
		"accepted_connections": h.Receiver.AcceptedConnections,
		"rejected_connections": h.Receiver.RejectedConnections,
		"closed_connections":   h.Receiver.ClosedConnections,
		"handshakes":           h.Receiver.Handshakes,
		"handshake_errors":     h.Receiver.HandshakeErrors,
		"received_frames":      h.Receiver.ReceivedFrames,
		"read_errors":          h.Receiver.ReadErrors,
		"interrupted_reads":    h.Receiver.InterruptedReads,
		"invalid_frames":       h.Receiver.InvalidFrames,
		"unresolved_starts":    h.Receiver.UnresolvedStarts,
		"ignored_frames":       h.Receiver.IgnoredFrames,
		"verified_starts":      h.Receiver.VerifiedStarts,
		"callbacks_completed":  h.Receiver.CallbacksCompleted,
		"sender_drop_frames":   h.Receiver.SenderDropFrames,
		"queue_drops":          h.Receiver.QueueDrops,
		"canceled_starts":      h.Receiver.CanceledStarts,
		"recheck_rejected":     h.RecheckRejected,
		"export_submitted":     h.ExportSubmitted,
		"listener_failures":    h.ListenerFailures,
	}
	for key, value := range counts {
		r.AddAttributes(attribute.Int64(key, int64(min(value, uint64(1<<63-1)))))
	}
	Logger().Emit(ctx, r)
}
