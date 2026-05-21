// Package otelsetup is a node-agent-specific wrapper around
// github.com/kubescape/go-logger/otelsetup. It delegates provider
// initialisation to the shared package and adds the node-agent-specific
// slow-evaluation threshold, named accessors, and structured alert log
// emission.
package otelsetup

import (
	"context"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	gotelsetup "github.com/kubescape/go-logger/otelsetup"
	"go.opentelemetry.io/otel"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// ProviderConfig is a type alias for the shared config so callers in this
// module need not import go-logger/otelsetup directly.
type ProviderConfig = gotelsetup.ProviderConfig

// slowEvalThresholdNs is the configured slow-evaluation threshold in
// nanoseconds. Set inside InitProviders from OTEL_SLOW_EVAL_THRESHOLD_MS
// (default 5ms) and read by callers via SlowEvalThreshold().
var slowEvalThresholdNs atomic.Int64

// SlowEvalThreshold returns the threshold above which rule evaluations should
// emit a trace span.
func SlowEvalThreshold() time.Duration {
	return time.Duration(slowEvalThresholdNs.Load())
}

// Tracer returns the global node-agent Tracer.
func Tracer() trace.Tracer {
	return otel.GetTracerProvider().Tracer("node-agent")
}

// Logger returns the global node-agent Logger.
func Logger() otellog.Logger {
	return global.GetLoggerProvider().Logger("node-agent")
}

// Meter returns the global node-agent Meter.
func Meter() metric.Meter {
	return otel.GetMeterProvider().Meter("node-agent")
}

// InitProviders initialises OTEL providers via the shared go-logger package
// and resolves the node-agent-specific slow-evaluation threshold.
func InitProviders(ctx context.Context, cfg ProviderConfig) (shutdown func(context.Context) error, err error) {
	thresholdMs := int64(5)
	if v := os.Getenv("OTEL_SLOW_EVAL_THRESHOLD_MS"); v != "" {
		if parsed, perr := strconv.ParseInt(v, 10, 64); perr == nil && parsed > 0 {
			thresholdMs = parsed
		}
	}
	slowEvalThresholdNs.Store(thresholdMs * int64(time.Millisecond))

	return gotelsetup.InitProviders(ctx, cfg)
}

// AlertLogAttrs is the structured attribute payload for EmitAlertLogRecord.
// MalwareSignature is optional — leave empty for non-malware alerts.
type AlertLogAttrs struct {
	RuleID           string
	AlertType        string
	ContainerName    string
	Namespace        string
	PodName          string
	Image            string
	EventType        string
	MalwareSignature string
}

// EmitAlertLogRecord emits a structured "SecurityAlert" log record carrying
// all alert dimensions as record attributes so the back-office can
// index/filter without parsing the body.
func EmitAlertLogRecord(ctx context.Context, attrs AlertLogAttrs) {
	var r otellog.Record
	now := time.Now()
	r.SetTimestamp(now)
	r.SetObservedTimestamp(now)
	r.SetBody(otellog.StringValue("SecurityAlert"))
	r.SetSeverity(otellog.SeverityWarn1)
	r.SetSeverityText("WARN")
	r.AddAttributes(
		otellog.String("rule_id", attrs.RuleID),
		otellog.String("alert_type", attrs.AlertType),
		otellog.String("container_name", attrs.ContainerName),
		otellog.String("namespace", attrs.Namespace),
		otellog.String("pod_name", attrs.PodName),
		otellog.String("image", attrs.Image),
		otellog.String("event_type", attrs.EventType),
	)
	if attrs.MalwareSignature != "" {
		r.AddAttributes(otellog.String("malware.signature", attrs.MalwareSignature))
	}
	Logger().Emit(ctx, r)
}
