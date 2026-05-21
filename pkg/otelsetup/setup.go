// Package otelsetup initializes OpenTelemetry providers (Tracer + Logger) for
// the node-agent. It is intentionally a thin wrapper around the OTEL SDK that
// owns endpoint resolution, ARMO authentication header injection, and an
// in-memory ring buffer log processor used for retroactive log export.
//
// Ordering constraint: callers MUST invoke InitProviders before any code that
// captures global.GetLoggerProvider() at construction time (e.g. the
// kubescape/go-logger structuredlogger).  Once InitProviders returns, the
// global TracerProvider and LoggerProvider are set; instruments obtained via
// the Tracer() / Logger() accessor functions below will route to the real
// exporters.
package otelsetup

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// ProviderConfig carries the inputs InitProviders needs to construct OTEL
// providers and (when targeting ARMO) authenticate with the back-office.
//
// AccountID and AccessKey are sourced from cmd/main.go lines 97-98 — they are
// read once at startup and become stale if /etc/credentials is rotated. This
// is a known v1 limitation; document in docs/CONFIGURATION.md.
type ProviderConfig struct {
	ServiceName    string
	ServiceVersion string
	NodeName       string
	PodName        string
	Namespace      string
	ClusterName    string
	AccountID      string // clusterData.AccountID (cmd/main.go:97)
	AccessKey      string // accessKey from /etc/credentials (cmd/main.go:98)
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

// slowEvalThresholdNs is the configured slow-evaluation threshold in
// nanoseconds. It is set ONLY inside InitProviders from the
// OTEL_SLOW_EVAL_THRESHOLD_MS env var (default 5ms) and read by callers via
// SlowEvalThreshold().
var slowEvalThresholdNs atomic.Int64

// SlowEvalThreshold returns the threshold above which rule evaluations should
// emit a trace span. Reads from a package-level atomic populated by
// InitProviders — one source of truth.
func SlowEvalThreshold() time.Duration {
	return time.Duration(slowEvalThresholdNs.Load())
}

// Tracer returns the global node-agent Tracer. Use this instead of capturing a
// package-level var so the tracer is always resolved AFTER InitProviders has
// installed the real TracerProvider.
func Tracer() trace.Tracer {
	return otel.GetTracerProvider().Tracer("node-agent")
}

// Logger returns the global node-agent Logger. Same rationale as Tracer().
func Logger() otellog.Logger {
	return global.GetLoggerProvider().Logger("node-agent")
}

// Meter returns the global node-agent Meter. Use this instead of capturing a
// package-level var so the meter is always resolved AFTER InitProviders has
// installed the real MeterProvider.
func Meter() metric.Meter {
	return otel.GetMeterProvider().Meter("node-agent")
}

// InitProviders initializes the TracerProvider and LoggerProvider. It returns
// a combined shutdown func that flushes batches with a 5s timeout. When
// OTEL_EXPORTER_OTLP_ENDPOINT is unset or targets ARMO without credentials,
// providers fall back to no-op (no panics, no log noise).
func InitProviders(ctx context.Context, cfg ProviderConfig) (shutdown func(context.Context) error, err error) {
	applyLegacyEnvAliases()

	// Resolve slow-eval threshold (default 5ms).
	thresholdMs := int64(5)
	if v := os.Getenv("OTEL_SLOW_EVAL_THRESHOLD_MS"); v != "" {
		if parsed, perr := strconv.ParseInt(v, 10, 64); perr == nil && parsed > 0 {
			thresholdMs = parsed
		}
	}
	slowEvalThresholdNs.Store(thresholdMs * int64(time.Millisecond))

	// Resolve endpoints once — never let the SDK re-read env for
	// security-sensitive paths (would let an attacker who can flip env after
	// startup retarget telemetry past our gating decision).
	baseEndpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	traceEndpoint := coalesce(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"), baseEndpoint)
	logEndpoint := coalesce(os.Getenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"), baseEndpoint)
	metricEndpoint := coalesce(os.Getenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"), baseEndpoint)

	// No endpoint configured — return a no-op shutdown so AC6 is honoured:
	// agent starts cleanly, zero data exported, no connection retries.
	if traceEndpoint == "" && logEndpoint == "" && metricEndpoint == "" {
		logger.L().Debug("OTEL endpoint unset; telemetry disabled")
		otel.SetTracerProvider(tracenoop.NewTracerProvider())
		otel.SetTextMapPropagator(propagation.TraceContext{})
		return func(context.Context) error { return nil }, nil
	}

	traceIsARMO := traceEndpoint != "" && isARMOEndpoint(traceEndpoint)
	logIsARMO := logEndpoint != "" && isARMOEndpoint(logEndpoint)
	metricIsARMO := metricEndpoint != "" && isARMOEndpoint(metricEndpoint)

	// ARMO endpoint without credentials -> force no-op to prevent silent
	// 401 retry storms.
	if (traceIsARMO || logIsARMO || metricIsARMO) && cfg.AccessKey == "" {
		logger.L().Warning("ARMO OTEL endpoint configured but no credentials; telemetry disabled")
		otel.SetTracerProvider(tracenoop.NewTracerProvider())
		otel.SetTextMapPropagator(propagation.TraceContext{})
		return func(context.Context) error { return nil }, nil
	}

	// Build ARMO headers only when the target hostname matches AND
	// credentials are present. For non-ARMO endpoints these stay nil.
	var traceHeaders, logHeaders map[string]string
	if traceIsARMO {
		traceHeaders = map[string]string{
			"X-API-Key":       cfg.AccessKey,
			"X-Customer-GUID": cfg.AccountID,
		}
	}
	if logIsARMO {
		logHeaders = map[string]string{
			"X-API-Key":       cfg.AccessKey,
			"X-Customer-GUID": cfg.AccountID,
		}
	}

	// Resource attributes shared by every signal.
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

	// --- TracerProvider ---------------------------------------------------
	var tp *sdktrace.TracerProvider
	if traceEndpoint != "" {
		var traceOpts []otlptracegrpc.Option
		if strings.Contains(traceEndpoint, "://") {
			traceOpts = append(traceOpts, otlptracegrpc.WithEndpointURL(traceEndpoint))
		} else {
			traceOpts = append(traceOpts, otlptracegrpc.WithEndpoint(traceEndpoint))
		}
		if len(traceHeaders) > 0 {
			traceOpts = append(traceOpts, otlptracegrpc.WithHeaders(traceHeaders))
		}
		spanExporter, err := otlptracegrpc.New(ctx, traceOpts...)
		if err != nil {
			return nil, err
		}
		tp = sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(spanExporter),
			sdktrace.WithResource(res),
		)
		otel.SetTracerProvider(tp)
	} else {
		otel.SetTracerProvider(tracenoop.NewTracerProvider())
	}
	otel.SetTextMapPropagator(propagation.TraceContext{})

	// --- LoggerProvider ---------------------------------------------------
	ringBuf := &RingBufferLogProcessor{}
	var logProvider *sdklog.LoggerProvider
	if logEndpoint != "" {
		var logOpts []otlploggrpc.Option
		if strings.Contains(logEndpoint, "://") {
			logOpts = append(logOpts, otlploggrpc.WithEndpointURL(logEndpoint))
		} else {
			logOpts = append(logOpts, otlploggrpc.WithEndpoint(logEndpoint))
		}
		if len(logHeaders) > 0 {
			logOpts = append(logOpts, otlploggrpc.WithHeaders(logHeaders))
		}
		logExporter, err := otlploggrpc.New(ctx, logOpts...)
		if err != nil {
			if tp != nil {
				_ = tp.Shutdown(ctx)
			}
			return nil, err
		}
		logProvider = sdklog.NewLoggerProvider(
			sdklog.WithResource(res),
			sdklog.WithProcessor(sdklog.NewBatchProcessor(logExporter)),
			sdklog.WithProcessor(ringBuf),
		)
		global.SetLoggerProvider(logProvider)
	}

	// --- MeterProvider -------------------------------------------
	var mp *sdkmetric.MeterProvider
	if metricEndpoint != "" {
		var metricHeaders map[string]string
		if metricIsARMO {
			metricHeaders = map[string]string{
				"X-API-Key":       cfg.AccessKey,
				"X-Customer-GUID": cfg.AccountID,
			}
		}
		var metricOpts []otlpmetricgrpc.Option
		if strings.Contains(metricEndpoint, "://") {
			metricOpts = append(metricOpts, otlpmetricgrpc.WithEndpointURL(metricEndpoint))
		} else {
			metricOpts = append(metricOpts, otlpmetricgrpc.WithEndpoint(metricEndpoint))
		}
		if len(metricHeaders) > 0 {
			metricOpts = append(metricOpts, otlpmetricgrpc.WithHeaders(metricHeaders))
		}
		metricExporter, err := otlpmetricgrpc.New(ctx, metricOpts...)
		if err != nil {
			if tp != nil {
				_ = tp.Shutdown(ctx)
			}
			if logProvider != nil {
				_ = logProvider.Shutdown(ctx)
			}
			return nil, err
		}
		mp = sdkmetric.NewMeterProvider(
			sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter)),
			sdkmetric.WithResource(res),
		)
		otel.SetMeterProvider(mp)
	}

	// --- Debug HTTP listener (gated) --------------------------------------
	var debugSrv *http.Server
	if os.Getenv("ENABLE_DEBUG_LISTENER") == "true" && logProvider != nil {
		port := coalesce(os.Getenv("OTEL_DEBUG_PORT"), "6062")
		l := logProvider.Logger("node-agent/ringbuf")
		mux := http.NewServeMux()
		mux.HandleFunc("POST /debug/flush-ring-buffer", func(w http.ResponseWriter, r *http.Request) {
			ringBuf.FlushToBackend(r.Context(), l)
			w.WriteHeader(http.StatusNoContent)
		})
		debugSrv = &http.Server{
			Addr:              "localhost:" + port,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			if err := debugSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.L().Warning("otel debug listener stopped", helpers.Error(err))
			}
		}()
	}

	// Combined shutdown with a fresh 5s timeout (callers' ctx may already be
	// cancelled when defer fires, which would skip flushing).
	shutdown = func(_ context.Context) error {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var tpErr, logErr, mpErr, debugErr error
		if tp != nil {
			tpErr = tp.Shutdown(shutdownCtx)
		}
		if logProvider != nil {
			logErr = logProvider.Shutdown(shutdownCtx)
		}
		if mp != nil {
			mpErr = mp.Shutdown(shutdownCtx)
		}
		if debugSrv != nil {
			debugErr = debugSrv.Shutdown(shutdownCtx)
		}
		return errors.Join(tpErr, logErr, mpErr, debugErr)
	}
	return shutdown, nil
}

// EmitAlertLogRecord emits a structured "SecurityAlert" log record carrying
// all alert dimensions as record attributes (NOT log body) so the back-office
// can index/filter without parsing the body.
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

// RingBufferLogProcessor keeps the last 7500 log records in memory so
// operators can flush them retroactively via the debug HTTP listener after a
// suspicious event is observed.
type RingBufferLogProcessor struct {
	buf  [7500]sdklog.Record
	head int
	tail int
	size int
	mu   sync.Mutex
}

// OnEmit clones the record (sdk/log Records are not concurrent-safe — the
// upstream BatchProcessor may mutate them after our return) and inserts it
// into the ring buffer.
func (p *RingBufferLogProcessor) OnEmit(_ context.Context, r *sdklog.Record) error {
	clone := r.Clone()
	p.mu.Lock()
	p.buf[p.head] = clone
	p.head = (p.head + 1) % len(p.buf)
	if p.size < len(p.buf) {
		p.size++
	} else {
		p.tail = (p.tail + 1) % len(p.buf)
	}
	p.mu.Unlock()
	return nil
}

// Enabled always returns true — the ring buffer captures every record so a
// retroactive flush has the full context.
func (p *RingBufferLogProcessor) Enabled(_ context.Context, _ sdklog.EnabledParameters) bool {
	return true
}

// Shutdown is a no-op — the buffer is in-memory only; nothing to flush to
// disk.
func (p *RingBufferLogProcessor) Shutdown(_ context.Context) error { return nil }

// ForceFlush is a no-op for the same reason.
func (p *RingBufferLogProcessor) ForceFlush(_ context.Context) error { return nil }

// FlushToBackend re-emits buffered records through the provided log.Logger so
// the LoggerProvider's existing BatchProcessor handles delivery. Do NOT call
// the raw exporter.Export here — that would race with the BatchProcessor's
// single-consumer goroutine.
func (p *RingBufferLogProcessor) FlushToBackend(ctx context.Context, l otellog.Logger) {
	p.mu.Lock()
	records := make([]sdklog.Record, p.size)
	for i := 0; i < p.size; i++ {
		records[i] = p.buf[(p.tail+i)%len(p.buf)]
	}
	p.mu.Unlock()
	for i := range records {
		l.Emit(ctx, sdkRecordToLogRecord(&records[i]))
	}
}

// sdkRecordToLogRecord copies the user-visible fields of an sdk/log Record
// onto a fresh log.Record. The SDK-side Record is used by processors; the
// log.Logger.Emit path expects the upstream log.Record type.
func sdkRecordToLogRecord(r *sdklog.Record) otellog.Record {
	var out otellog.Record
	out.SetTimestamp(r.Timestamp())
	out.SetObservedTimestamp(r.ObservedTimestamp())
	out.SetSeverity(r.Severity())
	out.SetSeverityText(r.SeverityText())
	out.SetBody(r.Body())
	out.SetEventName(r.EventName())
	r.WalkAttributes(func(kv otellog.KeyValue) bool {
		out.AddAttributes(kv)
		return true
	})
	return out
}

// applyLegacyEnvAliases maps the older OTEL_COLLECTOR_SVC env var onto the
// standard OTEL_EXPORTER_OTLP_ENDPOINT so existing deployments keep working
// after the cmd/main.go rewrite. The legacy var wins only when the standard
// one is unset (existing OTEL_EXPORTER_OTLP_ENDPOINT users are not disturbed).
func applyLegacyEnvAliases() {
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" {
		if legacy := os.Getenv("OTEL_COLLECTOR_SVC"); legacy != "" {
			_ = os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", legacy)
		}
	}
}

// isARMOEndpoint reports whether the resolved endpoint targets the ARMO
// back-office. It uses net/url to extract the hostname so a customer-hosted
// collector named `otel.armosec.io.evil.example` cannot trick us into
// shipping ARMO credentials via suffix matching.
func isARMOEndpoint(rawEndpoint string) bool {
	if os.Getenv("ARMO_OTEL_AUTH") == "true" {
		return true
	}
	if rawEndpoint == "" {
		return false
	}
	s := rawEndpoint
	if !strings.Contains(s, "://") {
		// gRPC endpoints are typically "host:port" — prepend "//" so
		// url.Parse populates the Host field (authority section) rather
		// than treating the whole string as a path.
		s = "//" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return u.Hostname() == "otel.armosec.io"
}

// coalesce returns the first non-empty string.
func coalesce(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
