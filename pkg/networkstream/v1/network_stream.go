package networkstream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/utils-k8s-go/wlid"
	"github.com/cenkalti/backoff/v5"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/common"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/processtree"
	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	timeoutDefaultSeconds = 5 // Default timeout for HTTP requests if not set in the config
)

type NetworkStream struct {
	networkEventsStorage      apitypes.NetworkStream
	eventsStorageMutex        sync.RWMutex // Mutex to protect access to networkEventsStorage.Containers
	cfg                       config.Config
	ctx                       context.Context
	k8sObjectCache            objectcache.K8sObjectCache
	dnsResolver               dnsmanager.DNSResolver
	k8sInventory              common.K8sInventoryCache
	nodeName                  string
	httpClient                *http.Client
	eventsNotificationChannel chan apitypes.NetworkStream
	dnsSupport                bool
	processTreeManager        processtree.ProcessTreeManager
}

func NewNetworkStream(ctx context.Context, cfg config.Config, k8sObjectCache objectcache.K8sObjectCache, dnsResolver dnsmanager.DNSResolver, nodeName string, eventsNotificationChannel chan apitypes.NetworkStream, dnsSupport bool, processTreeManager processtree.ProcessTreeManager) (*NetworkStream, error) {
	var k8sInventory common.K8sInventoryCache

	if cfg.KubernetesMode {
		var err error
		k8sInventory, err = common.GetK8sInventoryCache()
		if err != nil || k8sInventory == nil {
			return nil, fmt.Errorf("creating k8s inventory cache: %w", err)
		}
		k8sInventory.Start() // We do not stop it here, as we need it to be running for the whole lifetime of the NetworkStream.
	}

	var timeoutSeconds int
	if cfg.Exporters.HTTPExporterConfig != nil && cfg.Exporters.HTTPExporterConfig.TimeoutSeconds > 0 {
		timeoutSeconds = cfg.Exporters.HTTPExporterConfig.TimeoutSeconds
	} else {
		timeoutSeconds = timeoutDefaultSeconds
	}

	ns := NetworkStream{
		networkEventsStorage: apitypes.NetworkStream{
			Entities: make(map[string]apitypes.NetworkStreamEntity),
		},
		cfg:            cfg,
		ctx:            ctx,
		k8sObjectCache: k8sObjectCache,
		dnsResolver:    dnsResolver,
		k8sInventory:   k8sInventory,
		httpClient: &http.Client{
			Timeout: time.Duration(timeoutSeconds) * time.Second,
		},
		nodeName:                  nodeName,
		eventsNotificationChannel: eventsNotificationChannel,
		dnsSupport:                dnsSupport,
		processTreeManager:        processTreeManager,
	}

	// Create the host entity
	ns.networkEventsStorage.Entities[nodeName] = apitypes.NetworkStreamEntity{
		Kind:     apitypes.NetworkStreamEntityKindHost,
		Inbound:  make(map[string]apitypes.NetworkStreamEvent),
		Outbound: make(map[string]apitypes.NetworkStreamEvent),
	}

	return &ns, nil
}

func (ns *NetworkStream) ContainerCallback(notif containercollection.PubSubEvent) {
	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		ns.eventsStorageMutex.Lock()
		ns.networkEventsStorage.Entities[notif.Container.Runtime.ContainerID] = apitypes.NetworkStreamEntity{
			Kind: apitypes.NetworkStreamEntityKindContainer,
			NetworkStreamEntityContainer: apitypes.NetworkStreamEntityContainer{
				ContainerName: notif.Container.Runtime.ContainerName,
				ContainerID:   notif.Container.Runtime.ContainerID,
				PodNamespace:  notif.Container.K8s.Namespace,
				PodName:       notif.Container.K8s.PodName,
			},
			Inbound:  make(map[string]apitypes.NetworkStreamEvent),
			Outbound: make(map[string]apitypes.NetworkStreamEvent),
		}
		ns.eventsStorageMutex.Unlock()
		if ns.k8sObjectCache != nil {
			go ns.enrichWorkloadDetails(notif.Container.Runtime.ContainerID)
		}
	case containercollection.EventTypeRemoveContainer:
		ns.eventsStorageMutex.Lock()
		delete(ns.networkEventsStorage.Entities, notif.Container.Runtime.ContainerID)
		ns.eventsStorageMutex.Unlock()
	}
}

func (ns *NetworkStream) enrichWorkloadDetails(containerID string) {
	sharedData, err := ns.waitForSharedContainerData(containerID)
	if err != nil {
		logger.L().Error("NetworkStream - failed to get shared container data", helpers.Error(err),
			helpers.String("container ID", containerID))
		return
	}

	if sharedData == nil {
		logger.L().Error("NetworkStream - shared data is nil", helpers.String("container ID", containerID))
		return
	}

	ns.eventsStorageMutex.Lock()
	container, exists := ns.networkEventsStorage.Entities[containerID]
	if !exists {
		ns.eventsStorageMutex.Unlock()
		logger.L().Error("NetworkStream - container no longer exists", helpers.String("container ID", containerID))
		return
	}

	container.WorkloadName = wlid.GetNameFromWlid(sharedData.Wlid)
	container.WorkloadKind = wlid.GetKindFromWlid(sharedData.Wlid)
	ns.networkEventsStorage.Entities[containerID] = container
	ns.eventsStorageMutex.Unlock()
}

func (ns *NetworkStream) waitForSharedContainerData(containerID string) (*objectcache.WatchedContainerData, error) {
	return backoff.Retry(context.Background(), func() (*objectcache.WatchedContainerData, error) {
		if sharedData := ns.k8sObjectCache.GetSharedContainerData(containerID); sharedData != nil {
			return sharedData, nil
		}
		return nil, fmt.Errorf("container %s not found in shared data", containerID)
	}, backoff.WithBackOff(backoff.NewExponentialBackOff()))
}

// Periodically send the network events to the exporter
func (ns *NetworkStream) Start() {
	go func() {
		ticker := time.NewTicker(ns.cfg.NetworkStreamingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ns.ctx.Done():
				logger.L().Info("NetworkStream - stopping")
				return
			case <-ticker.C:
				ns.eventsStorageMutex.Lock()
				// Send the network events to the notification channel
				if ns.eventsNotificationChannel != nil {
					ns.eventsNotificationChannel <- ns.networkEventsStorage
					// Add a small delay to ensure consumers have time to process
					time.Sleep(100 * time.Millisecond)
				}

				// Remove process tree from events (to reduce size)
				removeProcessTreeFromEvents(&ns.networkEventsStorage)

				// Send the network events to the exporter
				if err := ns.sendNetworkEvent(&ns.networkEventsStorage); err != nil {
					logger.L().Error("NetworkStream - failed to send network events", helpers.Error(err))
				}

				// Clear the storage
				for entityId := range ns.networkEventsStorage.Entities {
					entity := ns.networkEventsStorage.Entities[entityId]
					entity.Inbound = make(map[string]apitypes.NetworkStreamEvent)
					entity.Outbound = make(map[string]apitypes.NetworkStreamEvent)
					ns.networkEventsStorage.Entities[entityId] = entity
				}
				// Re-create the host entity
				ns.networkEventsStorage.Entities[ns.nodeName] = apitypes.NetworkStreamEntity{
					Kind:     apitypes.NetworkStreamEntityKindHost,
					Inbound:  make(map[string]apitypes.NetworkStreamEvent),
					Outbound: make(map[string]apitypes.NetworkStreamEvent),
				}
				ns.eventsStorageMutex.Unlock()
				logger.L().Debug("NetworkStream - sent network events")
			}
		}
	}()
}

func (ns *NetworkStream) ReportEvent(eventType utils.EventType, event utils.K8sEvent) {
	switch eventType {
	case utils.NetworkEventType:
		networkEvent, ok := event.(*tracernetworktype.Event)
		if !ok {
			return
		}

		if networkEvent.PktType == "HOST" && networkEvent.PodHostIP == networkEvent.DstEndpoint.Addr || networkEvent.DstEndpoint.Addr == "127.0.0.1" {
			return // Ignore localhost events
		}

		ns.handleNetworkEvent(networkEvent)
	case utils.DnsEventType:
		if !ns.dnsSupport {
			return
		}

		dnsEvent, ok := event.(*tracerdnstype.Event)
		if !ok {
			return
		}
		if !ns.shouldReportDnsEvent(dnsEvent) {
			return
		}

		ns.handleDnsEvent(dnsEvent)

	default:
		logger.L().Error("NetworkStream - unknown event type", helpers.String("event type", string(eventType)))
	}
}

func (ns *NetworkStream) handleDnsEvent(event *tracerdnstype.Event) {
	ns.eventsStorageMutex.Lock()
	defer ns.eventsStorageMutex.Unlock()

	entityId := event.Runtime.ContainerID
	if entityId == "" || ns.k8sObjectCache == nil {
		entityId = ns.nodeName
	}

	entity, ok := ns.networkEventsStorage.Entities[entityId]
	if !ok {
		logger.L().Error("NetworkStream - entity not found", helpers.String("entity ID", entityId))
		return
	}

	// We get only DNS response events, so we put them in the outbound map
	if _, exists := entity.Outbound[event.DNSName]; exists {
		// If the event already exists, we can skip it
		return
	}

	networkEvent := apitypes.NetworkStreamEvent{
		Timestamp: time.Unix(0, int64(event.Timestamp)),
		DNSName:   event.DNSName,
		Port:      int32(event.DstPort),
		Protocol:  apitypes.NetworkStreamEventProtocolDNS,
		Kind:      apitypes.EndpointKindRaw,
	}

	processTree := ns.getProcessTreeByPid(event.Runtime.ContainerID, event.Pid, event.Comm)
	networkEvent.ProcessTree = &processTree

	entity.Outbound[event.DNSName] = networkEvent
	ns.networkEventsStorage.Entities[entityId] = entity
}

func (hns *NetworkStream) shouldReportDnsEvent(dnsEvent *tracerdnstype.Event) bool {
	if dnsEvent.DNSName == "" {
		return false
	}

	if strings.HasSuffix(dnsEvent.DNSName, "in-addr.arpa.") {
		return false
	}

	if strings.HasSuffix(dnsEvent.DNSName, "svc.cluster.local.") {
		return false
	}

	return true
}

func (ns *NetworkStream) handleNetworkEvent(event *tracernetworktype.Event) {
	endpointID := getNetworkEndpointIdentifier(event)

	ns.eventsStorageMutex.Lock()
	defer ns.eventsStorageMutex.Unlock()

	entityId := event.Runtime.ContainerID
	if entityId == "" || ns.k8sObjectCache == nil {
		entityId = ns.nodeName
	}

	entity, ok := ns.networkEventsStorage.Entities[entityId]
	if !ok {
		logger.L().Error("NetworkStream - entity not found", helpers.String("entity ID", entityId))
		return
	}

	if event.PktType == "OUTGOING" {
		if _, exists := entity.Outbound[endpointID]; exists {
			// If the event already exists, we can skip it
			return
		}
		networkEvent := ns.buildNetworkEvent(event)
		entity.Outbound[endpointID] = networkEvent
	} else {
		if _, exists := entity.Inbound[endpointID]; exists {
			// If the event already exists, we can skip it
			return
		}
		networkEvent := ns.buildNetworkEvent(event)
		entity.Inbound[endpointID] = networkEvent
	}
	ns.networkEventsStorage.Entities[entityId] = entity
}

func (ns *NetworkStream) buildNetworkEvent(event *tracernetworktype.Event) apitypes.NetworkStreamEvent {
	var domain string
	var ok bool
	if event.PktType == "OUTGOING" {
		domain, ok = ns.dnsResolver.ResolveIPAddress(event.DstEndpoint.Addr)
		if !ok {
			// Try to resolve the domain name
			domains, err := net.LookupAddr(event.DstEndpoint.Addr)
			if err != nil {
				domain = ""
			} else {
				if len(domains) > 0 {
					domain = domains[0]
				}
			}
		}
	} else {
		domain, _ = ns.dnsResolver.ResolveIPAddress(event.DstEndpoint.Addr)
	}

	networkEvent := apitypes.NetworkStreamEvent{
		Timestamp: time.Unix(0, int64(event.Timestamp)),
		IPAddress: event.DstEndpoint.Addr,
		DNSName:   domain,
		Port:      int32(event.Port),
		Protocol:  apitypes.NetworkStreamEventProtocol(event.Proto),
	}

	if apitypes.EndpointKind(event.DstEndpoint.Kind) == apitypes.EndpointKindPod {
		slimPod := ns.k8sInventory.GetPodByIp(event.DstEndpoint.Addr)
		if slimPod != nil {
			networkEvent.PodName = slimPod.Name
			networkEvent.PodNamespace = slimPod.Namespace

			workloadKind := ""
			workloadName := ""

			if len(slimPod.OwnerReferences) > 0 {
				workloadKind = slimPod.OwnerReferences[0].Kind
				if WorkloadKind(workloadKind) == ReplicaSet {
					workloadKind = string(Deployment)
				}
				// TODO: handle similar cases for CronJob -> Job -> Pod.
				workloadName = extractWorkloadName(slimPod.Name, WorkloadKind(workloadKind))
			}

			networkEvent.WorkloadName = workloadName
			networkEvent.WorkloadKind = workloadKind
			networkEvent.WorkloadNamespace = slimPod.Namespace
		}
	} else if apitypes.EndpointKind(event.DstEndpoint.Kind) == apitypes.EndpointKindService {
		slimService := ns.k8sInventory.GetSvcByIp(event.DstEndpoint.Addr)
		if slimService != nil {
			networkEvent.ServiceName = slimService.Name
			networkEvent.ServiceNamespace = slimService.Namespace
		}
	}

	networkEvent.Kind = apitypes.EndpointKind(event.DstEndpoint.Kind)

	processTree := ns.getProcessTreeByPid(event.Runtime.ContainerID, event.Pid, event.Comm)
	networkEvent.ProcessTree = &processTree

	return networkEvent
}

func (ns *NetworkStream) getProcessTreeByPid(containerID string, pid uint32, comm string) apitypes.ProcessTree {
	if containerID == "" || ns.k8sObjectCache == nil {
		// If we don't have a container ID, we can't get the process tree
		// So we just return the PID
		return apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				PID: pid,
			},
		}
	}

	processTree, err := ns.processTreeManager.GetBranch(pid, containerID)
	if err != nil {
		logger.L().Debug("NetworkStream - failed to get process tree", helpers.Error(err), helpers.Int("pid", int(pid)))
		return apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				PID: pid,
			},
		}
	}

	return apitypes.ProcessTree{
		ProcessTree: processTree,
	}
}

func (ns *NetworkStream) sendNetworkEvent(networkStream *apitypes.NetworkStream) error {
	if !ns.cfg.KubernetesMode || ns.cfg.Exporters.HTTPExporterConfig == nil {
		return nil
	}

	if isEmptyNetworkStream(networkStream) {
		logger.L().Debug("no events in network stream, skipping")
	}

	// create a GenericCRD with NetworkStream as Spec
	crd := apitypes.GenericCRD[apitypes.NetworkStream]{
		Kind:       "NetworkStreams",
		ApiVersion: "kubescape.io/v1",
		Metadata: apitypes.Metadata{
			Name: ns.nodeName,
		},
		Spec: *networkStream,
	}
	// create the JSON representation of the crd
	bodyBytes, err := json.Marshal(crd)
	if err != nil {
		return fmt.Errorf("marshal network stream: %w", err)
	}
	bodyReader := bytes.NewReader(bodyBytes)
	// prepare the request
	req, err := http.NewRequest(ns.cfg.Exporters.HTTPExporterConfig.Method,
		ns.cfg.Exporters.HTTPExporterConfig.URL+"/v1/networkstreams", bodyReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	for _, header := range ns.cfg.Exporters.HTTPExporterConfig.Headers {
		req.Header.Set(header.Key, header.Value)
	}
	// send the request
	resp, err := ns.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("non-2xx status code: %d", resp.StatusCode)
	}
	// discard the body
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return fmt.Errorf("clear response body: %w", err)
	}
	return nil
}

func getNetworkEndpointIdentifier(event *tracernetworktype.Event) string {
	return fmt.Sprintf("%s/%d/%s", event.DstEndpoint.Addr, event.Port, event.Proto)
}

func isEmptyNetworkStream(networkStream *apitypes.NetworkStream) bool {
	if len(networkStream.Entities) == 0 {
		return true
	}
	for _, entity := range networkStream.Entities {
		if len(entity.Inbound) > 0 || len(entity.Outbound) > 0 {
			return false
		}
	}
	return true
}

func removeProcessTreeFromEvents(networkStream *apitypes.NetworkStream) {
	for entityId, entity := range networkStream.Entities {
		for eventId, event := range entity.Inbound {
			event.ProcessTree = nil
			entity.Inbound[eventId] = event
		}
		for eventId, event := range entity.Outbound {
			event.ProcessTree = nil
			entity.Outbound[eventId] = event
		}
		networkStream.Entities[entityId] = entity
	}
}
