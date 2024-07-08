package containerwatcher

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	tracerantitampering "github.com/kubescape/node-agent/pkg/ebpf/gadgets/antitampering/tracer"
	tracerantitamperingtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/antitampering/types"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func (ch *IGContainerWatcher) tracerantitamperingtypeEventCallback(event *tracerantitamperingtype.Event) {
	if event.Type != types.NORMAL {
		// dropped event
		logger.L().Ctx(ch.ctx).Warning("tracerantitamperingtype tracer got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
		return
	}

	ch.antitampWorkerChan <- event
}

func (ch *IGContainerWatcher) startantitamperingTracing() error {
	if err := ch.tracerCollection.AddTracer(antitamperingTraceName, ch.containerSelector); err != nil {
		return fmt.Errorf("adding tracer: %w", err)
	}

	// Get mount namespace map to filter by containers
	tracerantitamperingtypeMountnsmap, err := ch.tracerCollection.TracerMountNsMap(antitamperingTraceName)
	if err != nil {
		return fmt.Errorf("getting tracerantitamperingMountnsmap: %w", err)
	}

	go func() {
		for event := range ch.antitampWorkerChan {
			ch.antitamperingWorkerPool.Invoke(*event)
		}
	}()

	allowedPidsMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "allowed_pids",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1024,
	})
	if err != nil {
		return fmt.Errorf("creating allowedPidsMap: %w", err)
	}

	restrictedMapsNamesMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "restricted_maps_names",
		Type:       ebpf.Hash,
		KeySize:    16,
		ValueSize:  4,
		MaxEntries: 1024,
	})
	if err != nil {
		return fmt.Errorf("creating restrictedMapsNamesMap: %w", err)
	}

	// Initialize allowed pids map with the pid of the agent.
	agentPid := os.Getpid()
	if err := allowedPidsMap.Put(uint32(agentPid), uint32(agentPid)); err != nil {
		return fmt.Errorf("putting agent pid in allowedPidsMap: %w", err)
	}

	// Initialize restricted maps names map with the name of the restricted maps.
	restrictedMapsNames := []string{"gadget_heap", "gadget_mntns_filter_map"}
	for _, name := range restrictedMapsNames {
		key := make([]byte, 16)
		copy(key, name)
		if err := restrictedMapsNamesMap.Put(key, []byte{1, 0, 0, 0}); err != nil {
			return fmt.Errorf("putting restricted map name in restrictedMapsNamesMap: %w", err)
		}
	}

	tracerantitamperingConfig := &tracerantitampering.Config{
		MountnsMap:          tracerantitamperingtypeMountnsmap,
		AllowedPids:         allowedPidsMap,
		RestrictedMapsNames: restrictedMapsNamesMap,
	}

	tracertracerantitamperingtype, err := tracerantitampering.NewTracer(tracerantitamperingConfig, ch.containerCollection, ch.tracerantitamperingtypeEventCallback)
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}
	ch.antitamperingTracer = tracertracerantitamperingtype

	return nil
}

func (ch *IGContainerWatcher) stopAntitamperingTracing() error {
	// Stop tracerantitamperingtype tracer
	if err := ch.tracerCollection.RemoveTracer(antitamperingTraceName); err != nil {
		return fmt.Errorf("removing tracer: %w", err)
	}
	ch.antitamperingTracer.Stop()
	return nil
}
