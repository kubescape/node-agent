package otelsetup

import (
	"context"

	"github.com/kubescape/node-agent/pkg/gvisor"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
)

// EmitRuntimeStart exports an observation through the existing OTEL log batch
// processor. It is intentionally not a SecurityAlert or a host eBPF event.
// No delivery acknowledgement is implied; OTEL's bounded queue can drop logs.
func EmitRuntimeStart(ctx context.Context, event gvisor.Observation) {
	var record otellog.Record
	record.SetTimestamp(event.ObservedAt)
	record.SetObservedTimestamp(event.ObservedAt)
	record.SetSeverity(otellog.SeverityInfo)
	record.SetBody(attribute.StringValue("RuntimeObservation"))
	record.AddAttributes(
		attribute.String("source", "gvisor_trace"),
		attribute.String("kind", "container_started"),
		attribute.String("identity_status", "verified"),
		attribute.String("identity_origin", "local_cri_and_kubernetes"),
		attribute.String("node", event.Node),
		attribute.String("container.id", event.Identity.ContainerID),
		attribute.String("sandbox_id", event.Identity.SandboxID),
		attribute.String("runtime_handler", event.Identity.RuntimeHandler),
		attribute.String("namespace", event.Identity.Namespace),
		attribute.String("pod_name", event.Identity.PodName),
		attribute.String("pod_uid", event.Identity.PodUID),
		attribute.String("container_name", event.Identity.ContainerName),
		attribute.Int64("sender_reported_drops", int64(event.Dropped)),
	)
	Logger().Emit(ctx, record)
}
