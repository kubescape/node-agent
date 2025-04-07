package networkstream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/utils-k8s-go/wlid"
	"github.com/cenkalti/backoff/v5"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/common"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/utils"
)

type NetworkStream struct {
	networkEventsStorage apitypes.NetworkStream
	eventsStorageMutex   sync.RWMutex // Mutex to protect access to networkEventsStorage.Containers
	cfg                  config.Config
	ctx                  context.Context
	k8sObjectCache       objectcache.K8sObjectCache
	dnsResolver          dnsmanager.DNSResolver
	k8sInventory         common.K8sInventoryCache
	k8sClient            k8sclient.K8sClientInterface

	nodeName   string
	httpClient *http.Client
}

func NewNetworkStream(ctx context.Context, cfg config.Config, k8sObjectCache objectcache.K8sObjectCache, dnsResolver dnsmanager.DNSResolver, k8sClient k8sclient.K8sClientInterface, nodeName string) (*NetworkStream, error) {
	k8sInventory, err := common.GetK8sInventoryCache()
	if err != nil || k8sInventory == nil {
		return nil, fmt.Errorf("creating k8s inventory cache: %w", err)
	}
	k8sInventory.Start() // We do not stop it here, as we need it to be running for the whole lifetime of the NetworkStream.

	return &NetworkStream{
		networkEventsStorage: apitypes.NetworkStream{
			Entities: make(map[string]apitypes.NetworkStreamEntity),
		},
		cfg:            cfg,
		ctx:            ctx,
		k8sObjectCache: k8sObjectCache,
		dnsResolver:    dnsResolver,
		k8sInventory:   k8sInventory,
		k8sClient:      k8sClient,
		httpClient: &http.Client{
			Timeout: time.Duration(cfg.Exporters.HTTPExporterConfig.TimeoutSeconds) * time.Second,
		},
		nodeName: nodeName,
	}, nil
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

		go ns.enrichWorkloadDetails(notif.Container.Runtime.ContainerID)
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

func (ns *NetworkStream) waitForSharedContainerData(containerID string) (*utils.WatchedContainerData, error) {
	return backoff.Retry(context.Background(), func() (*utils.WatchedContainerData, error) {
		if sharedData := ns.k8sObjectCache.GetSharedContainerData(containerID); sharedData != nil {
			return sharedData, nil
		}
		return nil, fmt.Errorf("container %s not found in shared data", containerID)
	}, backoff.WithBackOff(backoff.NewExponentialBackOff()))
}

// Periodically send the network events to the exporter
func (ns *NetworkStream) Start() {
	go func() {
		ticker := time.NewTicker(ns.cfg.UpdateDataPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-ns.ctx.Done():
				logger.L().Info("NetworkStream - stopping")
				return
			case <-ticker.C:
				ns.eventsStorageMutex.Lock()
				if err := ns.sendNetworkEvent(&ns.networkEventsStorage); err != nil {
					logger.L().Error("NetworkStream - failed to send network events", helpers.Error(err))
				}
				// Clear the storage
				for containerID := range ns.networkEventsStorage.Entities {
					container := ns.networkEventsStorage.Entities[containerID]
					container.Inbound = make(map[string]apitypes.NetworkStreamEvent)
					container.Outbound = make(map[string]apitypes.NetworkStreamEvent)
					ns.networkEventsStorage.Entities[containerID] = container
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

		if networkEvent.PktType == "HOST" && networkEvent.PodHostIP == networkEvent.DstEndpoint.Addr {
			return // Ignore localhost events
		}

		ns.handleNetworkEvent(networkEvent)
	default:
		logger.L().Error("NetworkStream - unknown event type", helpers.String("event type", string(eventType)))
	}
}

func (ns *NetworkStream) handleNetworkEvent(event *tracernetworktype.Event) {
	endpointID := getNetworkEndpointIdentifier(event)

	ns.eventsStorageMutex.Lock()
	defer ns.eventsStorageMutex.Unlock()

	container, ok := ns.networkEventsStorage.Entities[event.Runtime.ContainerID]
	if !ok {
		logger.L().Error("NetworkStream - container not found", helpers.String("container ID", event.Runtime.ContainerID))
		return
	}

	if event.PktType == "OUTGOING" {
		if _, exists := container.Outbound[endpointID]; exists {
			// If the event already exists, we can skip it
			return
		}
		networkEvent := ns.buildNetworkEvent(event)
		container.Outbound[endpointID] = networkEvent
	} else {
		if _, exists := container.Inbound[endpointID]; exists {
			// If the event already exists, we can skip it
			return
		}
		networkEvent := ns.buildNetworkEvent(event)
		container.Inbound[endpointID] = networkEvent
	}
	ns.networkEventsStorage.Entities[event.Runtime.ContainerID] = container
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
				if utils.WorkloadKind(workloadKind) == utils.ReplicaSet {
					workloadKind = string(utils.Deployment)
				}
				// TODO: handle similar cases for CronJob -> Job -> Pod.
				workloadName = utils.ExtractWorkloadName(slimPod.Name, utils.WorkloadKind(workloadKind))
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

	return networkEvent
}

func (ns *NetworkStream) sendNetworkEvent(networkStream *apitypes.NetworkStream) error {
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
