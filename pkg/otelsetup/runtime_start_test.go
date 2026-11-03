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
