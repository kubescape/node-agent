package tracers

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/socketenricher"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/otelsetup"
	"github.com/kubescape/node-agent/pkg/utils"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	orasoci "oras.land/oras-go/v2/content/oci"
)

const (
	dnsImageName = "ghcr.io/inspektor-gadget/gadget/trace_dns:v0.48.1"
	dnsTraceName = "trace_dns"

	// dnsStartMaxRetries bounds retries of a failed gadget start. Startup
	// failures in this class are transient/timing-dependent (see
	// armosec/private-node-agent#511: a CO-RE/BTF cache race in the pinned
	// cilium/ebpf fork can abort relocation for any kernel module with
	// split BTF present at that moment), so a single failed attempt does
	// not mean the gadget can never start.
	dnsStartMaxRetries = 5
)

var _ containerwatcher.TracerInterface = (*DNSTracer)(nil)

// DNSTracer implements TracerInterface for events
type DNSTracer struct {
	eventCallback containerwatcher.ResultCallback

	mu        sync.Mutex
	gadgetCtx *gadgetcontext.GadgetContext
	// cancel stops the retry loop started by Start, independently of
	// whichever GadgetContext is currently in flight. See Stop.
	cancel context.CancelFunc

	kubeManager        operators.DataOperator
	ociStore           *orasoci.ReadOnlyStore
	runtime            runtime.Runtime
	socketEnricherOp   *socketenricher.SocketEnricher
	thirdPartyEnricher containerwatcher.TaskBasedEnricher

	// forwarding is nil unless WithDNSRuleForwarding enabled it. With it nil
	// the tracer behaves exactly as before: only answered responses enter the
	// pipeline.
	forwarding *dnsForwarding
}

// DNSTracerOption configures optional DNSTracer behaviour.
type DNSTracerOption func(*DNSTracer)

// WithDNSRuleForwarding forwards DNS queries and error responses to the rule
// manager, as rule-only events, according to cfg. With cfg.Enabled false it is
// a no-op. See docs/features/dns-query-rule-forwarding.md.
func WithDNSRuleForwarding(cfg config.DNSRuleForwardingConfig) DNSTracerOption {
	return func(dt *DNSTracer) {
		if !cfg.Enabled {
			return
		}
		dt.forwarding = newDNSForwarding(cfg.ExcludedSuffixes)
	}
}

// NewDNSTracer creates a new tracer
func NewDNSTracer(
	kubeManager operators.DataOperator,
	runtime runtime.Runtime,
	ociStore *orasoci.ReadOnlyStore,
	eventCallback containerwatcher.ResultCallback,
	thirdPartyEnricher containerwatcher.TaskBasedEnricher,
	socketEnricherOp *socketenricher.SocketEnricher,
	opts ...DNSTracerOption,
) *DNSTracer {
	dt := &DNSTracer{
		eventCallback:      eventCallback,
		kubeManager:        kubeManager,
		ociStore:           ociStore,
		runtime:            runtime,
		thirdPartyEnricher: thirdPartyEnricher,
		socketEnricherOp:   socketEnricherOp,
	}
	for _, opt := range opts {
		opt(dt)
	}
	return dt
}

// builtinExcludedDNSSuffixes are never forwarded as rule-only events: they are
// the bulk of unique names in a cluster (ndots search-suffix expansion of
// external names, reverse lookups) and can never carry exfiltrated data to an
// external server.
var builtinExcludedDNSSuffixes = []string{".cluster.local.", ".in-addr.arpa.", ".ip6.arpa."}

// dnsForwarding holds the forwarding policy and its counter.
type dnsForwarding struct {
	excludedSuffixes []string
	counter          metric.Int64Counter
}

func newDNSForwarding(extraSuffixes []string) *dnsForwarding {
	suffixes := make([]string, 0, len(builtinExcludedDNSSuffixes)+len(extraSuffixes))
	suffixes = append(suffixes, builtinExcludedDNSSuffixes...)
	for _, s := range extraSuffixes {
		if s = config.NormalizeDNSSuffix(s); s != "" {
			suffixes = append(suffixes, s)
		}
	}
	counter, _ := otelsetup.Meter().Int64Counter(
		"node_agent.dns.rule_forwarding.total",
		metric.WithDescription("DNS packets classified by the rule-forwarding filter, by outcome"),
	)
	return &dnsForwarding{excludedSuffixes: suffixes, counter: counter}
}

func (f *dnsForwarding) excluded(name string) bool {
	name = strings.ToLower(name)
	for _, s := range f.excludedSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

func (f *dnsForwarding) count(outcome dnsOutcome) {
	if f == nil || f.counter == nil {
		return
	}
	f.counter.Add(context.Background(), 1, metric.WithAttributes(attribute.String("outcome", string(outcome))))
}

// dnsOutcome is the counter label for one classified packet.
type dnsOutcome string

const (
	dnsOutcomeAnswered      dnsOutcome = "answered"       // response with answers: the pre-existing path
	dnsOutcomeQuery         dnsOutcome = "query"          // forwarded, rule-only
	dnsOutcomeErrorResponse dnsOutcome = "error_response" // NXDOMAIN/SERVFAIL/REFUSED...: forwarded, rule-only
	dnsOutcomeSkippedSuffix dnsOutcome = "skipped_suffix" // excluded name
	dnsOutcomeSkippedNodata dnsOutcome = "skipped_nodata" // NOERROR with no answers: repeats the query, dropped
	dnsOutcomeDropped       dnsOutcome = "dropped"        // forwarding off, or empty name
)

// classifyDNS decides whether a parsed DNS packet enters the pipeline and
// whether it is rule-only. fwd nil means forwarding is off, which reproduces
// the historical filter exactly: only responses with answers pass.
func classifyDNS(e utils.DNSEvent, fwd *dnsForwarding) (forward bool, ruleOnly bool, outcome dnsOutcome) {
	isResponse := e.GetQr() == utils.DNSPktTypeResponse
	if isResponse && e.GetNumAnswers() > 0 {
		return true, false, dnsOutcomeAnswered
	}
	if fwd == nil {
		return false, false, dnsOutcomeDropped
	}
	name := e.GetDNSName()
	if name == "" {
		return false, false, dnsOutcomeDropped
	}
	if fwd.excluded(name) {
		return false, false, dnsOutcomeSkippedSuffix
	}
	if !isResponse {
		return true, true, dnsOutcomeQuery
	}
	// A NOERROR response without answers (NODATA, typically AAAA for an
	// IPv4-only name) only repeats the question the query already carried.
	if e.GetRcode() == RCodeSuccess.String() {
		return false, false, dnsOutcomeSkippedNodata
	}
	return true, true, dnsOutcomeErrorResponse
}

// newGadgetContext builds a fresh GadgetContext for a single run attempt and
// records it as the tracer's current one, so Stop() always cancels whichever
// attempt is in flight.
func (dt *DNSTracer) newGadgetContext(ctx context.Context) *gadgetcontext.GadgetContext {
	gadgetCtx := gadgetcontext.New(
		ctx,
		// This is the image that contains the gadget we want to run.
		dnsImageName,
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			dt.kubeManager,
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
			dt.socketEnricherOp,
			NewDnsOperator(),
			dt.eventOperator(),
		),
		gadgetcontext.WithName(dnsTraceName),
		gadgetcontext.WithOrasReadonlyTarget(dt.ociStore),
	)

	dt.mu.Lock()
	dt.gadgetCtx = gadgetCtx
	dt.mu.Unlock()

	return gadgetCtx
}

// Start initializes and starts the tracer
func (dt *DNSTracer) Start(ctx context.Context) error {
	// The retry loop gets its own cancelable context, independent of
	// whichever GadgetContext is currently in flight, so Stop can halt
	// retries even between attempts (see Stop).
	ctx, cancel := context.WithCancel(ctx)
	dt.mu.Lock()
	dt.cancel = cancel
	dt.mu.Unlock()

	go func() {
		params := map[string]string{
			"operator.oci.ebpf.paths": "true", // CWD paths in events
		}

		attempt := 0
		bo := backoff.WithContext(backoff.WithMaxRetries(backoff.NewExponentialBackOff(), dnsStartMaxRetries-1), ctx)
		err := backoff.RetryNotify(func() error {
			attempt++
			// Each attempt gets its own GadgetContext: a failed run leaves
			// the previous one terminated, and it also becomes the current
			// one Stop() will cancel.
			gadgetCtx := dt.newGadgetContext(ctx)
			return dt.runtime.RunGadget(gadgetCtx, nil, params)
		}, bo, func(err error, next time.Duration) {
			logger.L().Warning("Error running gadget, retrying",
				helpers.String("gadget", dnsTraceName),
				helpers.Int("attempt", attempt),
				helpers.Error(err))
		})
		if err != nil {
			logger.L().Error("Error running gadget", helpers.String("gadget", dnsTraceName), helpers.Int("attempts", attempt), helpers.Error(err))
		}
	}()
	return nil
}

// Stop gracefully stops the tracer
func (dt *DNSTracer) Stop() error {
	if dt.socketEnricherOp != nil {
		dt.socketEnricherOp.Close()
	}

	dt.mu.Lock()
	cancel := dt.cancel
	gadgetCtx := dt.gadgetCtx
	dt.mu.Unlock()

	// Stop the retry loop first: canceling only the in-flight GadgetContext
	// below would make that one attempt fail, but RetryNotify would then
	// start a new one from a fresh, uncanceled context - retrying after
	// Stop was called. Canceling this context makes the backoff wrapper
	// give up instead.
	if cancel != nil {
		cancel()
	}
	if gadgetCtx != nil {
		gadgetCtx.Cancel()
	}
	return nil
}

// GetName returns the unique name of the tracer
func (dt *DNSTracer) GetName() string {
	return dnsTraceName
}

// GetEventType returns the event type this tracer produces
func (dt *DNSTracer) GetEventType() utils.EventType {
	return utils.DnsEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (dt *DNSTracer) IsEnabled(cfg config.Config) bool {
	if cfg.DDns {
		return false
	}
	return cfg.EnableNetworkTracing || cfg.EnableRuntimeDetection
}

func (dt *DNSTracer) eventOperator() operators.DataOperator {
	return simple.New(string(utils.DnsEventType),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				err := d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					// Classify on the packet in place and copy only what is
					// forwarded. Reads inside the subscribe callback are valid
					// without a copy, and most packets are dropped, so this
					// removes a DeepCopy per dropped packet.
					view := &utils.DatasourceEvent{Datasource: d, Data: data, EventType: utils.DnsEventType}
					forward, ruleOnly, outcome := classifyDNS(view, dt.forwarding)
					dt.forwarding.count(outcome)
					if !forward {
						return nil
					}
					dt.callback(&utils.DatasourceEvent{Datasource: d, Data: source.DeepCopy(data), EventType: utils.DnsEventType, RuleOnly: ruleOnly})
					return nil
				}, opPriority)
				if err != nil {
					return err
				}
			}
			return nil
		}), simple.WithPriority(opPriority),
	)
}

// callback hands an event that classifyDNS accepted to the pipeline.
func (dt *DNSTracer) callback(event utils.DNSEvent) {
	if dt.eventCallback != nil {
		// Extract container ID and process ID from the DNS event
		containerID := event.GetContainerID()
		processID := event.GetPID()

		dt.eventCallback(event, containerID, processID)
	}
}
