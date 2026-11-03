//go:build linux

package otelsetup

import (
	"context"
	"testing"

	"github.com/kubescape/node-agent/pkg/gvisor"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/log/logtest"
)

func TestGVisorHealthReportsStateAndLossWithoutIdentity(t *testing.T) {
	recorder := logtest.NewRecorder()
	previous := global.GetLoggerProvider()
	global.SetLoggerProvider(recorder)
	t.Cleanup(func() { global.SetLoggerProvider(previous) })
	for _, h := range []gvisor.Health{
		{},
		{Running: true, ListenerFailures: 2},
		{Running: true, Receiver: gvisor.Stats{Listening: true}},
		{Running: true, Receiver: gvisor.Stats{Listening: true, ActiveConnections: 1, QueueDrops: 3, CanceledStarts: 4, SenderDropFrames: 5}, RecheckRejected: 6, ExportSubmitted: 7},
	} {
		EmitGVisorHealth(context.Background(), h)
	}
	var records []logtest.Record
	for _, group := range recorder.Result() {
		records = append(records, group...)
	}
	if len(records) != 4 {
		t.Fatalf("got %d reports", len(records))
	}
	allowed := map[string]bool{}
	for _, key := range []string{"source", "state", "active_connections", "accepted_connections", "rejected_connections", "closed_connections", "handshakes", "handshake_errors", "received_frames", "read_errors", "interrupted_reads", "invalid_frames", "unresolved_starts", "ignored_frames", "verified_starts", "callbacks_completed", "sender_drop_frames", "queue_drops", "canceled_starts", "recheck_rejected", "export_submitted", "listener_failures"} {
		allowed[key] = true
	}
	for i, r := range records {
		if r.Body.AsString() != "RuntimeSourceHealth" || r.Severity != otellog.SeverityInfo || r.Timestamp.IsZero() {
			t.Fatal("wrong health contract")
		}
		got := map[string]any{}
		for _, attr := range r.Attributes {
			key := string(attr.Key)
			if !allowed[key] {
				t.Fatalf("unapproved field %s", key)
			}
			got[key] = attr.Value.AsInterface()
		}
		if len(got) != len(allowed) || got["source"] != "gvisor_trace" || got["state"] != []string{"stopped", "retrying_listener", "listening", "connected"}[i] {
			t.Fatalf("wrong health attributes: %v", got)
		}
		if i == 3 && (got["queue_drops"] != int64(3) || got["canceled_starts"] != int64(4) || got["sender_drop_frames"] != int64(5) || got["recheck_rejected"] != int64(6) || got["export_submitted"] != int64(7)) {
			t.Fatalf("loss stages missing: %v", got)
		}
	}
}
