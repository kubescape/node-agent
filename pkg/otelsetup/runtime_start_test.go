package otelsetup

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/gvisor"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/log/logtest"
)

func TestGVisorObservationUsesDistinctLogContract(t *testing.T) {
	recorder := logtest.NewRecorder()
	previous := global.GetLoggerProvider()
	global.SetLoggerProvider(recorder)
	t.Cleanup(func() { global.SetLoggerProvider(previous) })
	when := time.Now()
	EmitRuntimeStart(context.Background(), gvisor.Observation{
		Start:    gvisor.Start{Source: "gvisor_trace", ContainerID: "cid", ObservedAt: when, Dropped: 3},
		Identity: gvisor.Identity{ContainerID: "cid", SandboxID: "sid", RuntimeHandler: "runsc", Namespace: "apps", PodName: "pod", PodUID: "uid", ContainerName: "app"}, Node: "node",
	})
	var records []logtest.Record
	for _, group := range recorder.Result() {
		records = append(records, group...)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records", len(records))
	}
	r := records[0]
	if r.Body.AsString() != "RuntimeObservation" || r.Severity != otellog.SeverityInfo || !r.Timestamp.Equal(when) || !r.ObservedTimestamp.Equal(when) {
		t.Fatal("wrong observation semantics")
	}
	got := map[string]any{}
	for _, a := range r.Attributes {
		got[string(a.Key)] = a.Value.AsInterface()
	}
	want := map[string]any{"source": "gvisor_trace", "kind": "container_started", "identity_status": "verified", "identity_origin": "local_cri_and_kubernetes", "node": "node", "container.id": "cid", "sandbox_id": "sid", "runtime_handler": "runsc", "namespace": "apps", "pod_name": "pod", "pod_uid": "uid", "container_name": "app", "sender_reported_drops": int64(3)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected attributes: %#v", got)
	}
}

func TestGVisorStopUsesObservationContract(t *testing.T) {
	recorder := logtest.NewRecorder()
	previous := global.GetLoggerProvider()
	global.SetLoggerProvider(recorder)
	t.Cleanup(func() { global.SetLoggerProvider(previous) })
	when := time.Now()
	identity := gvisor.Identity{ContainerID: "cid", SandboxID: "sid", RuntimeHandler: "runsc", Namespace: "apps", PodName: "pod", PodUID: "uid", ContainerName: "app"}
	EmitRuntimeStop(context.Background(), gvisor.StopObservation{
		Stop: gvisor.Stop{Source: "gvisor_trace", ContainerID: "cid", ObservedAt: when, ExitCode: 143, Signal: 15, Dropped: 1}, Identity: identity, Node: "node"})
	EmitRuntimeStop(context.Background(), gvisor.StopObservation{
		Stop: gvisor.Stop{Source: "gvisor_trace", ContainerID: "cid", ObservedAt: when, ExitCode: 7}, Identity: identity, Node: "node"})
	var records []logtest.Record
	for _, group := range recorder.Result() {
		records = append(records, group...)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records", len(records))
	}
	for i, want := range []map[string]any{
		{"termination": "signaled", "exit_code": int64(143), "signal": int64(15), "sender_reported_drops": int64(1)},
		{"termination": "exited", "exit_code": int64(7), "signal": int64(0), "sender_reported_drops": int64(0)},
	} {
		r := records[i]
		if r.Body.AsString() != "RuntimeObservation" || !r.Timestamp.Equal(when) {
			t.Fatal("wrong stop semantics")
		}
		got := map[string]any{}
		for _, a := range r.Attributes {
			got[string(a.Key)] = a.Value.AsInterface()
		}
		if got["kind"] != "container_stopped" || got["source"] != "gvisor_trace" || got["pod_uid"] != "uid" || len(got) != 16 {
			t.Fatalf("unexpected stop attributes: %#v", got)
		}
		for key, value := range want {
			if got[key] != value {
				t.Fatalf("%s: got %v want %v", key, got[key], value)
			}
		}
	}
}
