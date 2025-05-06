package containerwatcher

import (
	"fmt"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection/networktracer"
	tracerdns "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/tracer"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func (ch *IGContainerWatcher) dnsEventCallback(event *tracerdnstype.Event) {
	if event.Type == types.DEBUG {
		return
	}

	if isDroppedEvent(event.Type, event.Message) {
		logger.L().Ctx(ch.ctx).Warning("dns tracer got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
		return
	}

	if strings.Contains(event.DNSName, "xmr.pool.minergate.com") {
		logger.L().Info("R1008 EnrichByMntNs",
			helpers.Interface("event.CommonData", event.CommonData),
			helpers.String("event.MountNsID", fmt.Sprintf("%d", event.MountNsID)),
			helpers.String("event.NetNsID", fmt.Sprintf("%d", event.NetNsID)),
		)
	}

	ch.containerCollection.EnrichByMntNs(&event.CommonData, event.MountNsID)
	// ch.containerCollection.EnrichByNetNs(&event.CommonData, event.NetNsID)

	ch.dnsWorkerChan <- event
}

func (ch *IGContainerWatcher) startDNSTracing() error {
	if err := ch.tracerCollection.AddTracer(dnsTraceName, ch.containerSelector); err != nil {
		return fmt.Errorf("adding tracer: %w", err)
	}

	tracerDns, err := tracerdns.NewTracer(&tracerdns.Config{GetPaths: true})
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}
	go func() {
		for event := range ch.dnsWorkerChan {
			_ = ch.dnsWorkerPool.Invoke(*event)
		}
	}()

	tracerDns.SetSocketEnricherMap(ch.socketEnricher.SocketsMap())
	tracerDns.SetEventHandler(ch.dnsEventCallback)

	err = tracerDns.RunWorkaround()
	if err != nil {
		return fmt.Errorf("running workaround: %w", err)
	}

	ch.dnsTracer = tracerDns

	config := &networktracer.ConnectToContainerCollectionConfig[tracerdnstype.Event]{
		Tracer:   ch.dnsTracer,
		Resolver: ch.containerCollection,
		Selector: ch.containerSelector,
		Base:     tracerdnstype.Base,
	}

	_, err = networktracer.ConnectToContainerCollection(config)
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}

	return nil
}

func (ch *IGContainerWatcher) stopDNSTracing() error {
	// Stop dns tracer
	if err := ch.tracerCollection.RemoveTracer(dnsTraceName); err != nil {
		return fmt.Errorf("removing tracer: %w", err)
	}
	ch.dnsTracer.Close()
	return nil
}
