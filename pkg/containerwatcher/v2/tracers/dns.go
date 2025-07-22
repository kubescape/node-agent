package tracers

import (
	"context"
	"fmt"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection/networktracer"
	tracerdns "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/tracer"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/socketenricher"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/utils"
)

const dnsTraceName = "trace_dns"

var _ containerwatcher.TracerInterface = (*DNSTracer)(nil)

// DNSTracer implements TracerInterface for DNS events
type DNSTracer struct {
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection
	containerSelector   containercollection.ContainerSelector
	eventCallback       func(utils.K8sEvent, string, uint32)
	tracer              *tracerdns.Tracer
	socketEnricher      *socketenricher.SocketEnricher
}

// NewDNSTracer creates a new DNS tracer
func NewDNSTracer(
	containerCollection *containercollection.ContainerCollection,
	tracerCollection *tracercollection.TracerCollection,
	containerSelector containercollection.ContainerSelector,
	eventCallback func(utils.K8sEvent, string, uint32),
	socketEnricher *socketenricher.SocketEnricher,
) *DNSTracer {
	return &DNSTracer{
		containerCollection: containerCollection,
		tracerCollection:    tracerCollection,
		containerSelector:   containerSelector,
		eventCallback:       eventCallback,
		socketEnricher:      socketEnricher,
	}
}

// Start initializes and starts the DNS tracer
func (dt *DNSTracer) Start(ctx context.Context) error {
	if err := dt.tracerCollection.AddTracer(dnsTraceName, dt.containerSelector); err != nil {
		return fmt.Errorf("adding DNS tracer: %w", err)
	}

	tracerDns, err := tracerdns.NewTracer(&tracerdns.Config{GetPaths: true})
	if err != nil {
		return fmt.Errorf("creating DNS tracer: %w", err)
	}

	if dt.socketEnricher != nil {
		tracerDns.SetSocketEnricherMap(dt.socketEnricher.SocketsMap())
	} else {
		logger.L().Error("DNSTracer - socket enricher is nil")
	}

	tracerDns.SetEventHandler(dt.dnsEventCallback)

	err = tracerDns.RunWorkaround()
	if err != nil {
		return fmt.Errorf("running workaround: %w", err)
	}

	dt.tracer = tracerDns

	config := &networktracer.ConnectToContainerCollectionConfig[tracerdnstype.Event]{
		Tracer:   dt.tracer,
		Resolver: dt.containerCollection,
		Selector: dt.containerSelector,
		Base:     tracerdnstype.Base,
	}

	_, err = networktracer.ConnectToContainerCollection(config)
	if err != nil {
		return fmt.Errorf("connecting tracer to container collection: %w", err)
	}

	return nil
}

// Stop gracefully stops the DNS tracer
func (dt *DNSTracer) Stop() error {
	if dt.tracer != nil {
		dt.tracer.Close()
	}

	if err := dt.tracerCollection.RemoveTracer(dnsTraceName); err != nil {
		return fmt.Errorf("removing DNS tracer: %w", err)
	}

	return nil
}

// GetName returns the unique name of the tracer
func (dt *DNSTracer) GetName() string {
	return "dns_tracer"
}

// GetEventType returns the event type this tracer produces
func (dt *DNSTracer) GetEventType() utils.EventType {
	return utils.DnsEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (dt *DNSTracer) IsEnabled(cfg interface{}) bool {
	if config, ok := cfg.(config.Config); ok {
		return config.EnableNetworkTracing || config.EnableRuntimeDetection
	}
	return false
}

// dnsEventCallback handles DNS events from the tracer
func (dt *DNSTracer) dnsEventCallback(event *tracerdnstype.Event) {
	if event.Type == types.DEBUG {
		return
	}

	if event.Qr != tracerdnstype.DNSPktTypeResponse {
		return
	}

	if event.NumAnswers == 0 {
		return
	}

	if isDroppedEvent(event.Type, event.Message) {
		logger.L().Warning("dns tracer got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
		return
	}

	dt.containerCollection.EnrichByMntNs(&event.CommonData, event.MountNsID)
	dt.containerCollection.EnrichByNetNs(&event.CommonData, event.NetNsID)

	if dt.eventCallback != nil {
		// Extract container ID and process ID from the DNS event
		containerID := event.Runtime.ContainerID
		processID := event.Pid

		dt.eventCallback(event, containerID, processID)
	}
}
