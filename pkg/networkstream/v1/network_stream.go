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
	"github.com/goradd/maps"
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type NetworkStream struct {
	networkEventsStorage apitypes.NetworkTrafficEvents
	eventsStorageMutex   sync.RWMutex // Mutex to protect access to networkEventsStorage.Containers
	cfg                  config.Config
	ctx                  context.Context
	k8sObjectCache       objectcache.K8sObjectCache
	dnsResolver          dnsmanager.DNSResolver
	k8sInventory         common.K8sInventoryCache
	k8sClient            k8sclient.K8sClientInterface

	// Cache for owner references to avoid repeated lookups
	ownerCache maps.SafeMap[string, *metav1.OwnerReference]
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
		networkEventsStorage: apitypes.NetworkTrafficEvents{
			Containers: make(map[string]apitypes.NetworkTrafficEventContainer),
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
		ns.networkEventsStorage.Containers[notif.Container.Runtime.ContainerID] = apitypes.NetworkTrafficEventContainer{
			ContainerName: notif.Container.Runtime.ContainerName,
			ContainerID:   notif.Container.Runtime.ContainerID,
			PodNamespace:  notif.Container.K8s.Namespace,
			PodName:       notif.Container.K8s.PodName,
			Inbound:       make(map[string]apitypes.NetworkTrafficEvent),
			Outbound:      make(map[string]apitypes.NetworkTrafficEvent),
		}
		ns.eventsStorageMutex.Unlock()

		go ns.enrichWorkloadDetails(notif.Container.Runtime.ContainerID)
	case containercollection.EventTypeRemoveContainer:
		ns.eventsStorageMutex.Lock()
		delete(ns.networkEventsStorage.Containers, notif.Container.Runtime.ContainerID)
		ns.eventsStorageMutex.Unlock()
		// Invalidate the cache for the owner reference (it's okay if there are pods with multiple containers, we will just do the lookup again).
		ns.invalidateOwnerCache(notif.Container.K8s.Namespace, notif.Container.K8s.PodName)
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
	container, exists := ns.networkEventsStorage.Containers[containerID]
	if !exists {
		ns.eventsStorageMutex.Unlock()
		logger.L().Error("NetworkStream - container no longer exists", helpers.String("container ID", containerID))
		return
	}

	container.WorkloadName = wlid.GetNameFromWlid(sharedData.Wlid)
	container.WorkloadKind = wlid.GetKindFromWlid(sharedData.Wlid)
	ns.networkEventsStorage.Containers[containerID] = container
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
				for containerID := range ns.networkEventsStorage.Containers {
					container := ns.networkEventsStorage.Containers[containerID]
					container.Inbound = make(map[string]apitypes.NetworkTrafficEvent)
					container.Outbound = make(map[string]apitypes.NetworkTrafficEvent)
					ns.networkEventsStorage.Containers[containerID] = container
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
		ns.handleNetworkEvent(networkEvent)
	default:
		logger.L().Error("NetworkStream - unknown event type", helpers.String("event type", string(eventType)))
	}
}

func (ns *NetworkStream) handleNetworkEvent(event *tracernetworktype.Event) {
	endpointID := getNetworkEndpointIdentifier(event)

	ns.eventsStorageMutex.Lock()
	defer ns.eventsStorageMutex.Unlock()

	container, ok := ns.networkEventsStorage.Containers[event.Runtime.ContainerID]
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
	ns.networkEventsStorage.Containers[event.Runtime.ContainerID] = container
}

func (ns *NetworkStream) buildNetworkEvent(event *tracernetworktype.Event) apitypes.NetworkTrafficEvent {
	domain, ok := ns.dnsResolver.ResolveIPAddress(event.DstEndpoint.Addr)
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

	networkEvent := apitypes.NetworkTrafficEvent{
		Timestamp: time.Unix(0, int64(event.Timestamp)),
		IPAddress: event.DstEndpoint.Addr,
		DNSName:   domain,
		Port:      int32(event.Port),
		Protocol:  apitypes.NetworkTrafficEventProtocol(event.Proto),
	}

	if apitypes.EndpointKind(event.DstEndpoint.Kind) == apitypes.EndpointKindPod {
		slimPod := ns.k8sInventory.GetPodByIp(event.DstEndpoint.Addr)
		if slimPod != nil {
			networkEvent.PodName = slimPod.Name
			networkEvent.PodNamespace = slimPod.Namespace

			// Use the cache to get the top owner reference
			cacheKey := ns.getPodCacheKey(slimPod.Namespace, slimPod.Name)
			topOwner := ns.getCachedOwnerReference(cacheKey)

			if topOwner == nil {
				// Cache miss - look up the owner and cache the result
				var err error
				topOwner, err = ns.getTopOwnerReference(slimPod.Namespace, slimPod.Name, slimPod.OwnerReferences)
				if err != nil {
					logger.L().Error("Failed to get top owner reference",
						helpers.Error(err),
						helpers.String("pod", slimPod.Name),
						helpers.String("namespace", slimPod.Namespace))
				} else if topOwner != nil {
					// Cache the result for future lookups
					ns.cacheOwnerReference(cacheKey, topOwner)
				}
			}

			if topOwner != nil {
				networkEvent.WorkloadName = topOwner.Name
				networkEvent.WorkloadKind = topOwner.Kind
				logger.L().Debug("NetworkStream - found top owner reference", helpers.String("workload name", topOwner.Name),
					helpers.String("workload kind", topOwner.Kind), helpers.String("pod name", slimPod.Name),
					helpers.String("pod namespace", slimPod.Namespace))
			}
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

// Helper function to generate a cache key for a pod
func (ns *NetworkStream) getPodCacheKey(namespace, name string) string {
	return namespace + "/" + name
}

// Get an owner reference from the cache
func (ns *NetworkStream) getCachedOwnerReference(key string) *metav1.OwnerReference {
	if owner, exists := ns.ownerCache.Load(key); exists {
		return owner
	}
	return nil
}

// Store an owner reference in the cache
func (ns *NetworkStream) cacheOwnerReference(key string, owner *metav1.OwnerReference) {
	ns.ownerCache.Set(key, owner)
}

// Invalidate cache entries when needed
func (ns *NetworkStream) invalidateOwnerCache(namespace, podName string) {
	key := ns.getPodCacheKey(namespace, podName)
	ns.ownerCache.Delete(key)
}

func (ns *NetworkStream) sendNetworkEvent(networkStream *apitypes.NetworkTrafficEvents) error {
	// create a GenericCRD with NetworkTrafficEvents as Spec
	crd := apitypes.GenericCRD[apitypes.NetworkTrafficEvents]{
		Kind:       "NetworkStream",
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
		ns.cfg.Exporters.HTTPExporterConfig.URL+"/v1/networkstream", bodyReader)
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
