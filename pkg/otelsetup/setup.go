// Package otelsetup is a node-agent-specific wrapper around
// github.com/kubescape/go-logger/otelsetup. It delegates provider
// initialisation to the shared package and adds the node-agent-specific
// slow-evaluation threshold, named accessors, and structured alert log
// emission.
package otelsetup

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	gotelsetup "github.com/kubescape/go-logger/otelsetup"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	promexporter "go.opentelemetry.io/otel/exporters/prometheus"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
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
// When OTEL_METRICS_EXPORTER=prometheus, a Prometheus scrape endpoint is
// started on :8080/metrics in addition to (or instead of) OTLP metric export.
func InitProviders(ctx context.Context, cfg ProviderConfig) (shutdown func(context.Context) error, err error) {
	thresholdMs := int64(5)
	if v := os.Getenv("OTEL_SLOW_EVAL_THRESHOLD_MS"); v != "" {
		if parsed, perr := strconv.ParseInt(v, 10, 64); perr == nil && parsed > 0 {
			thresholdMs = parsed
		}
	}
	slowEvalThresholdNs.Store(thresholdMs * int64(time.Millisecond))

	baseShutdown, err := gotelsetup.InitProviders(ctx, cfg)
	if err != nil {
		return nil, err
	}

	// Prometheus metrics mode: set up a scrape endpoint and override the
	// MeterProvider. This is mutually exclusive with OTLP metric push — when
	// OTEL_METRICS_EXPORTER=prometheus is set, the OTLP metric exporter that
	// go-logger may have configured is replaced by the prometheus reader.
	if os.Getenv("OTEL_METRICS_EXPORTER") == "prometheus" {
		promShutdown, perr := initPrometheusMeterProvider(cfg)
		if perr != nil {
			_ = baseShutdown(ctx)
			return nil, perr
		}
		return func(ctx context.Context) error {
			return errors.Join(baseShutdown(ctx), promShutdown(ctx))
		}, nil
	}

	return baseShutdown, nil
}

// initPrometheusMeterProvider creates a prometheus.Exporter-backed MeterProvider,
// registers it as the global provider, and starts an HTTP server on :8080/metrics.
// Returns a shutdown func that stops the HTTP server and flushes the provider.
func initPrometheusMeterProvider(cfg ProviderConfig) (func(context.Context) error, error) {
	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(
		semconv.ServiceName(cfg.ServiceName),
		semconv.ServiceVersion(cfg.ServiceVersion),
		semconv.K8SClusterName(cfg.ClusterName),
		semconv.K8SNodeName(cfg.NodeName),
		semconv.K8SPodName(cfg.PodName),
		semconv.K8SNamespaceName(cfg.Namespace),
	))
	if err != nil {
		return nil, err
	}

	promExp, err := promexporter.New()
	if err != nil {
		return nil, err
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(promExp),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(mp)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	srv := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if serr := srv.ListenAndServe(); serr != nil && !errors.Is(serr, http.ErrServerClosed) {
			logger.L().Warning("otelsetup: prometheus metrics server stopped", helpers.Error(serr))
		}
	}()

	return func(ctx context.Context) error {
		_ = srv.Shutdown(ctx)
		return mp.Shutdown(ctx)
	}, nil
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
