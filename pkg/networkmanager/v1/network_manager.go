package v1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/networkmanager"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/node-agent/pkg/utils"

	"github.com/armosec/utils-k8s-go/wlid"
	"github.com/cenkalti/backoff/v4"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/google/uuid"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned/scheme"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	k8sv1beta1 "k8s.io/api/batch/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/utils/ptr"
)

type NetworkManager struct {
	cfg                           config.Config
	containerAndPodToWLIDMap      maps.SafeMap[string, string]
	watchedContainerChannels      maps.SafeMap[string, chan error]
	containerAndPodToDroppedEvent maps.SafeMap[string, bool]
	containerAndPodToEventsMap    maps.SafeMap[string, mapset.Set[networkmanager.NetworkEvent]]
	storageClient                 storage.StorageClient
	removedContainers             mapset.Set[string]
	trackedContainers             mapset.Set[string]
	k8sClient                     k8sclient.K8sClientInterface
	ctx                           context.Context
	dnsResolverClient             dnsmanager.DNSResolver
	preRunningContainerIDs        mapset.Set[string]
	k8sObjectCache                objectcache.K8sObjectCache
	clusterName                   string
}

var _ NetworkManagerClient = (*NetworkManager)(nil)

func CreateNetworkManager(ctx context.Context, cfg config.Config, k8sClient k8sclient.K8sClientInterface, storageClient storage.StorageClient, clusterName string, dnsResolverClient dnsmanager.DNSResolver, preRunningContainerIDs mapset.Set[string], k8sObjectCache objectcache.K8sObjectCache) *NetworkManager {
	return &NetworkManager{
		cfg:                    cfg,
		ctx:                    ctx,
		k8sClient:              k8sClient,
		k8sObjectCache:         k8sObjectCache,
		storageClient:          storageClient,
		clusterName:            clusterName,
		dnsResolverClient:      dnsResolverClient,
		preRunningContainerIDs: preRunningContainerIDs,
		trackedContainers:      mapset.NewSet[string](),
		removedContainers:      mapset.NewSet[string](),
	}
}

func (am *NetworkManager) ContainerCallback(notif containercollection.PubSubEvent) {
	k8sContainerID := utils.CreateK8sContainerID(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.ContainerName)
	ctx, span := otel.Tracer("").Start(am.ctx, "NetworkManager.ContainerCallback", trace.WithAttributes(attribute.String("containerID", notif.Container.Runtime.ContainerID), attribute.String("k8s workload", k8sContainerID)))
	defer span.End()

	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		if am.watchedContainerChannels.Has(notif.Container.Runtime.ContainerID) {
			logger.L().Debug("container already exist in memory", helpers.String("container ID", notif.Container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
			return
		}
		go am.handleContainerStarted(ctx, notif.Container, k8sContainerID)

	case containercollection.EventTypeRemoveContainer:
		channel := am.watchedContainerChannels.Get(notif.Container.Runtime.ContainerID)
		if channel != nil {
			channel <- utils.ContainerHasTerminatedError
		}
	}
}

func (am *NetworkManager) ReportDroppedEvent(containerID string, event tracernetworktype.Event) {
	am.containerAndPodToDroppedEvent.Set(containerID+event.K8s.PodName, true)
}

func (am *NetworkManager) ReportNetworkEvent(containerID string, event tracernetworktype.Event) {
	if err := am.waitForContainer(containerID); err != nil {
		return
	}
	if !am.isValidEvent(event) {
		return
	}

	networkEvent := &networkmanager.NetworkEvent{
		Port:     event.Port,
		Protocol: event.Proto,
		PktType:  event.PktType,
		Destination: networkmanager.Destination{
			Namespace: event.DstEndpoint.Namespace,
			Name:      event.DstEndpoint.Name,
			Kind:      networkmanager.EndpointKind(event.DstEndpoint.Kind),
			IPAddress: event.DstEndpoint.Addr,
		},
	}
	networkEvent.SetPodLabels(event.PodLabels)
	networkEvent.SetDestinationPodLabels(event.DstEndpoint.PodLabels)

	networkEventsSet := am.containerAndPodToEventsMap.Get(containerID + event.K8s.PodName)
	if am.containerAndPodToEventsMap.Get(containerID+event.K8s.PodName) == nil {
		networkEventsSet = mapset.NewSet[networkmanager.NetworkEvent]()
	}
	networkEventsSet.Add(*networkEvent)
	am.containerAndPodToEventsMap.Set(containerID+event.K8s.PodName, networkEventsSet)
}

// isValidEvent checks if the event is a valid event that should be saved
func (am *NetworkManager) isValidEvent(event tracernetworktype.Event) bool {
	// unknown type, shouldn't happen
	if event.PktType != networkmanager.HostPktType && event.PktType != networkmanager.OutgoingPktType {
		logger.L().Debug("NetworkManager - pktType is not HOST or OUTGOING", helpers.Interface("event", event))
		return false
	}

	// ignore localhost
	if event.PktType == networkmanager.HostPktType && event.PodHostIP == event.DstEndpoint.Addr {
		return false
	}

	// ignore host netns
	if event.K8s.HostNetwork {
		return false
	}

	return true
}

func (am *NetworkManager) handleContainerStarted(ctx context.Context, container *containercollection.Container, k8sContainerID string) {
	ctx, span := otel.Tracer("").Start(ctx, "NetworkManager.handleContainerStarted")
	defer span.End()

	watchedContainer := &utils.WatchedContainerData{
		ContainerID:      container.Runtime.ContainerID,
		UpdateDataTicker: time.NewTicker(am.cfg.InitialDelay),
		SyncChannel:      make(chan error, 10),
		K8sContainerID:   k8sContainerID,
	}
	am.watchedContainerChannels.Set(watchedContainer.ContainerID, watchedContainer.SyncChannel)
	am.removedContainers.Remove(container.Runtime.ContainerID)
	am.trackedContainers.Add(container.Runtime.ContainerID)
	// retrieve parent WL
	parentWL, err := am.getParentWorkloadFromContainer(container)
	if err != nil {
		logger.L().Warning("NetworkManager - failed to get parent workload", helpers.String("reason", err.Error()), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
		return
	}

	selector, err := getSelectorFromWorkload(parentWL)
	if err != nil {
		// if we get not selector, we can't create/update network neighbor
		logger.L().Warning("NetworkManager - failed to get selector", helpers.String("reason", err.Error()), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
		return
	}

	if selector == nil {
		// if we get not selector, we can't create/update network neighbor
		logger.L().Warning("NetworkManager - selector is nil", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
		return
	}

	// save container + pod to wlid map
	am.containerAndPodToWLIDMap.Set(container.Runtime.ContainerID+container.K8s.PodName, parentWL.GenerateWlid(am.clusterName))

	if err := am.monitorContainer(ctx, container, watchedContainer); err != nil {
		logger.L().Info("NetworkManager - stop monitor on container", helpers.String("reason", err.Error()), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
	}

	am.deleteResources(container)
}

func getSelectorFromWorkload(workload k8sinterface.IWorkload) (*metav1.LabelSelector, error) {
	if workload.GetKind() == "CronJob" {
		obj := workload.GetObject()
		jsonBytes, err := json.Marshal(obj)
		if err != nil {
			return nil, err
		}
		var cronjob k8sv1beta1.CronJob
		if err = json.Unmarshal(jsonBytes, &cronjob); err != nil {
			return nil, err
		}
		selector := &metav1.LabelSelector{
			MatchLabels: cronjob.Spec.JobTemplate.Spec.Template.ObjectMeta.Labels,
		}
		return selector, nil
	}

	selector, err := workload.GetSelector()
	if err != nil {
		return nil, err
	}
	return selector, nil
}

// TODO: use same function in relevancy
func (am *NetworkManager) getParentWorkloadFromContainer(container *containercollection.Container) (k8sinterface.IWorkload, error) {
	wl, err := am.k8sClient.GetWorkload(container.K8s.Namespace, "Pod", container.K8s.PodName)
	if err != nil {
		return nil, err
	}
	pod := wl.(*workloadinterface.Workload)

	// find parentWlid
	kind, name, err := am.k8sClient.CalculateWorkloadParentRecursive(pod)
	if err != nil {
		return nil, err
	}

	parentWorkload, err := am.k8sClient.GetWorkload(pod.GetNamespace(), kind, name)
	if err != nil {
		return nil, err
	}

	w := parentWorkload.(*workloadinterface.Workload)
	parentWlid := w.GenerateWlid(am.clusterName)

	err = wlid.IsWlidValid(parentWlid)
	if err != nil {
		return nil, err
	}

	return parentWorkload, nil
}

func (am *NetworkManager) deleteResources(container *containercollection.Container) {
	// clean up
	am.removedContainers.Add(container.Runtime.ContainerID)
	am.trackedContainers.Remove(container.Runtime.ContainerID)
	am.containerAndPodToWLIDMap.Delete(container.Runtime.ContainerID + container.K8s.PodName)
	am.containerAndPodToEventsMap.Delete(container.Runtime.ContainerID + container.K8s.PodName)
	am.containerAndPodToDroppedEvent.Delete(container.Runtime.ContainerID + container.K8s.PodName)
	am.watchedContainerChannels.Delete(container.Runtime.ContainerID)

}

func (am *NetworkManager) ContainerReachedMaxTime(containerID string) {
	if channel := am.watchedContainerChannels.Get(containerID); channel != nil {
		channel <- utils.ContainerReachedMaxTime
	}
}

func (am *NetworkManager) monitorContainer(ctx context.Context, container *containercollection.Container, watchedContainer *utils.WatchedContainerData) error {
	// set completion status & status as soon as we start monitoring the container
	if am.preRunningContainerIDs.Contains(container.Runtime.ContainerID) {
		watchedContainer.SetCompletionStatus(utils.WatchedContainerCompletionStatusPartial)
	} else {
		watchedContainer.SetCompletionStatus(utils.WatchedContainerCompletionStatusFull)
	}
	watchedContainer.SetStatus(utils.WatchedContainerStatusInitializing)
	am.saveNetworkEvents(ctx, container, watchedContainer)

	for {
		select {
		case <-watchedContainer.UpdateDataTicker.C:
			// adjust ticker after first tick
			if !watchedContainer.InitialDelayExpired {
				watchedContainer.InitialDelayExpired = true
				watchedContainer.UpdateDataTicker.Reset(am.cfg.UpdateDataPeriod)
			}

			watchedContainer.SetStatus(utils.WatchedContainerStatusReady)
			am.saveNetworkEvents(ctx, container, watchedContainer)
		case err := <-watchedContainer.SyncChannel:
			switch {
			case errors.Is(err, utils.ContainerReachedMaxTime):
				watchedContainer.SetStatus(utils.WatchedContainerStatusCompleted)
				am.saveNetworkEvents(ctx, container, watchedContainer)
				return nil
			case errors.Is(err, utils.ContainerHasTerminatedError):
				// if exit code is 0 we set the status to completed

				if objectcache.GetTerminationExitCode(am.k8sObjectCache, container.K8s.Namespace, container.K8s.PodName, container.K8s.ContainerName, container.Runtime.ContainerID) == 0 {
					watchedContainer.SetStatus(utils.WatchedContainerStatusCompleted)
				}
				am.saveNetworkEvents(ctx, container, watchedContainer)
				return nil
			}

			// TODO: @Amir should we handle too large?
		}
	}
}

// handleNetworkEvents retrieves network events from map, generate entries for CRD and sends a PATCH command to update them
func (am *NetworkManager) saveNetworkEvents(_ context.Context, container *containercollection.Container, watchedContainer *utils.WatchedContainerData) {
	// retrieve parent WL from internal map
	parentWlid := am.containerAndPodToWLIDMap.Get(container.Runtime.ContainerID + container.K8s.PodName)
	if parentWlid == "" {
		logger.L().Warning("NetworkManager - failed to get parent wlid from map", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("pod name", container.K8s.PodName))
		return
	}

	name := networkmanager.GenerateNetworkNeighborsNameFromWlid(parentWlid)
	namespace := wlid.GetNamespaceFromWlid(parentWlid)
	networkNeighborsExists := false
	networkNeighbors, err := am.storageClient.GetNetworkNeighbors(namespace, name)
	if err != nil {
		if strings.Contains(err.Error(), "the server is currently unable to handle the request") {
			logger.L().Warning("NetworkManager - failed to update network neighbor", helpers.String("reason", err.Error()), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", watchedContainer.K8sContainerID))
			return
		}
	}

	currSpec := v1beta1.NetworkNeighborsSpec{}
	if err == nil {
		networkNeighborsExists = true
		currSpec = networkNeighbors.Spec
	}

	if droppedEvents := am.containerAndPodToDroppedEvent.Get(container.Runtime.ContainerID + container.K8s.PodName); droppedEvents {
		watchedContainer.SetStatus(helpersv1.MissingRuntime)
	}

	networkEvents := am.containerAndPodToEventsMap.Get(container.Runtime.ContainerID + container.K8s.PodName)

	// update CRD based on events
	networkNeighborsSpec := am.generateNetworkNeighborsEntries(container.K8s.Namespace, networkEvents, currSpec)

	if networkNeighborsExists {
		// patch only if there are changes
		if len(networkNeighborsSpec.Egress) > 0 || len(networkNeighborsSpec.Ingress) > 0 || watchedContainer.StatusUpdated() {
			// send PATCH command using entries generated from events
			nn := &v1beta1.NetworkNeighbors{
				ObjectMeta: networkNeighbors.ObjectMeta,
				Spec: v1beta1.NetworkNeighborsSpec{
					Egress:  []v1beta1.NetworkNeighbor{},
					Ingress: []v1beta1.NetworkNeighbor{},
				},
			}
			if watchedContainer.StatusUpdated() {
				nn.ObjectMeta.Annotations = map[string]string{
					helpersv1.StatusMetadataKey:     string(watchedContainer.GetStatus()),
					helpersv1.CompletionMetadataKey: string(watchedContainer.GetCompletionStatus()),
				}
			}
			if len(networkNeighborsSpec.Egress) > 0 {
				nn.Spec.Egress = networkNeighborsSpec.Egress
			}
			if len(networkNeighborsSpec.Ingress) > 0 {
				nn.Spec.Ingress = networkNeighborsSpec.Ingress
			}
			if err := am.storageClient.PatchNetworkNeighborsIngressAndEgress(name, namespace, nn); err != nil {
				logger.L().Warning("NetworkManager - failed to patch network neighbor", helpers.String("reason", err.Error()), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", watchedContainer.K8sContainerID))
				return
			} else {
				logger.L().Debug("NetworkManager - patched network neighbor", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", watchedContainer.K8sContainerID))
			}
		}
	} else {
		// if not found, we need to create it
		// this can happen if the storage wasn't available when the container started
		parentWL, err := am.getParentWorkloadFromContainer(container)
		if err != nil {
			logger.L().Warning("NetworkManager - failed to get parent workload", helpers.String("reason", err.Error()), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("parent wlid", parentWlid))
			return
		}

		selector, err := parentWL.GetSelector()
		if err != nil {
			logger.L().Warning("NetworkManager - failed to get selector", helpers.String("reason", err.Error()), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("parent wlid", parentWlid))
			return
		}
		newNetworkNeighbors := networkmanager.GenerateNetworkNeighborsCRD(parentWL, selector, am.clusterName)

		// update spec and annotations
		networkNeighborsSpec.LabelSelector = *selector
		newNetworkNeighbors.Spec = networkNeighborsSpec
		newNetworkNeighbors.Annotations[helpersv1.StatusMetadataKey] = string(watchedContainer.GetStatus())
		newNetworkNeighbors.Annotations[helpersv1.CompletionMetadataKey] = string(watchedContainer.GetCompletionStatus())

		logger.L().Debug("NetworkManager - creating network neighbor", helpers.Interface("labels", selector), helpers.String("container ID", container.Runtime.ContainerID), helpers.Interface("labels", newNetworkNeighbors.Spec.LabelSelector))

		if err = am.storageClient.CreateNetworkNeighbors(newNetworkNeighbors, parentWL.GetNamespace()); err != nil {
			logger.L().Warning("NetworkManager - failed to create network neighbor", helpers.String("reason", err.Error()), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("parent wlid", parentWlid))
			return
		}
		logger.L().Debug("NetworkManager - created network neighbor", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", watchedContainer.K8sContainerID))
	}

	watchedContainer.ResetStatusUpdatedFlag()

	// remove events from map
	am.containerAndPodToEventsMap.Delete(container.Runtime.ContainerID + container.K8s.PodName)
}
func (am *NetworkManager) generateNetworkNeighborsEntries(namespace string, networkEvents mapset.Set[networkmanager.NetworkEvent], currSpec v1beta1.NetworkNeighborsSpec) v1beta1.NetworkNeighborsSpec {
	var networkNeighborsSpec v1beta1.NetworkNeighborsSpec

	// auxiliary maps to avoid duplicates
	ingressIdentifiersMap := make(map[string]v1beta1.NetworkNeighbor)
	egressIdentifiersMap := make(map[string]v1beta1.NetworkNeighbor)

	// auxiliary maps to avoid duplicates
	currIngressIdentifiersMap := make(map[string]bool)
	currEgressIdentifiersMap := make(map[string]bool)

	for i := range currSpec.Egress {
		if identifier, err := utils.GenerateNeighborsIdentifier(currSpec.Egress[i]); err == nil {
			currEgressIdentifiersMap[identifier] = true
		}
	}
	for i := range currSpec.Ingress {
		if identifier, err := utils.GenerateNeighborsIdentifier(currSpec.Ingress[i]); err == nil {
			currIngressIdentifiersMap[identifier] = true
		}
	}

	if networkEvents == nil {
		return networkNeighborsSpec
	}

	networkEventsIterator := networkEvents.Iterator()
	if networkEventsIterator == nil {
		return networkNeighborsSpec
	}

	for networkEvent := range networkEventsIterator.C {
		var neighborEntry v1beta1.NetworkNeighbor

		if networkEvent.Destination.Kind == networkmanager.EndpointKindPod {
			// for Pods, we need to remove the default labels
			neighborEntry.PodSelector = &metav1.LabelSelector{
				MatchLabels: networkmanager.FilterLabels(networkEvent.GetDestinationPodLabels()),
			}

			if namespaceLabels := utils.GetNamespaceMatchLabels(networkEvent.Destination.Namespace, namespace); namespaceLabels != nil {
				neighborEntry.NamespaceSelector = &metav1.LabelSelector{
					MatchLabels: namespaceLabels,
				}
			}

		} else if networkEvent.Destination.Kind == networkmanager.EndpointKindService {
			// for service, we need to retrieve it and use its selector
			svc, err := am.k8sClient.GetWorkload(networkEvent.Destination.Namespace, "Service", networkEvent.Destination.Name)
			if err != nil {
				logger.L().Warning("failed to get service", helpers.String("reason", err.Error()), helpers.String("service name", networkEvent.Destination.Name))
				continue
			}

			var selector map[string]string
			if svc.GetName() == "kubernetes" && svc.GetNamespace() == "default" {
				// the default service has no selectors, in addition, we want to save the default service address
				selector = svc.GetLabels()
				neighborEntry.IPAddress = networkEvent.Destination.IPAddress
			} else {
				selector = svc.GetServiceSelector()
			}
			if len(selector) == 0 {
				if err = am.handleServiceWithNoSelectors(networkEvent, egressIdentifiersMap, ingressIdentifiersMap); err != nil {
					logger.L().Warning("failed to handle service with no selectors", helpers.String("reason", err.Error()), helpers.String("service name", networkEvent.Destination.Name))
				}
				continue
			} else {
				neighborEntry.PodSelector = &metav1.LabelSelector{
					MatchLabels: selector,
				}
				if namespaceLabels := utils.GetNamespaceMatchLabels(networkEvent.Destination.Namespace, namespace); namespaceLabels != nil {
					neighborEntry.NamespaceSelector = &metav1.LabelSelector{
						MatchLabels: namespaceLabels,
					}
				}
			}

		} else {
			if networkEvent.Destination.IPAddress == "127.0.0.1" {
				// No need to generate for localhost
				continue
			}
			neighborEntry.IPAddress = networkEvent.Destination.IPAddress

			if am.dnsResolverClient != nil {
				domain, ok := am.dnsResolverClient.ResolveIPAddress(networkEvent.Destination.IPAddress)
				if ok {
					neighborEntry.DNS = domain
					neighborEntry.DNSNames = []string{domain}
				}
			}
		}

		saveNeighborEntry(networkEvent, neighborEntry, egressIdentifiersMap, ingressIdentifiersMap, currEgressIdentifiersMap, currIngressIdentifiersMap)

	}

	networkNeighborsSpec.Egress = make([]v1beta1.NetworkNeighbor, 0, len(egressIdentifiersMap))
	for _, neighborEntry := range egressIdentifiersMap {
		networkNeighborsSpec.Egress = append(networkNeighborsSpec.Egress, neighborEntry)
	}

	networkNeighborsSpec.Ingress = make([]v1beta1.NetworkNeighbor, 0, len(ingressIdentifiersMap))
	for _, neighborEntry := range ingressIdentifiersMap {
		networkNeighborsSpec.Ingress = append(networkNeighborsSpec.Ingress, neighborEntry)
	}

	return networkNeighborsSpec
}

// saveNeighborEntry encapsulates the logic of generating identifiers and adding the neighborEntry to the map
func saveNeighborEntry(networkEvent networkmanager.NetworkEvent, neighborEntry v1beta1.NetworkNeighbor, egressIdentifiersMap, ingressIdentifiersMap map[string]v1beta1.NetworkNeighbor, currEgressIdentifiersMap, currIngressIdentifiersMap map[string]bool) {

	portIdentifier := networkmanager.GeneratePortIdentifierFromEvent(networkEvent)

	neighborEntry.Ports = []v1beta1.NetworkPort{
		{
			Protocol: v1beta1.Protocol(networkEvent.Protocol),
			Port:     ptr.To(int32(networkEvent.Port)),
			Name:     portIdentifier,
		}}

	neighborEntry.Type = networkmanager.InternalTrafficType
	if neighborEntry.NamespaceSelector == nil && neighborEntry.PodSelector == nil {
		neighborEntry.Type = networkmanager.ExternalTrafficType
	}

	// generate identifier for this neighborEntry
	identifier, err := utils.GenerateNeighborsIdentifier(neighborEntry)
	if err != nil {
		// if we fail to hash, use a random identifier so at least we have the data on the crd
		logger.L().Debug("failed to hash identifier", helpers.String("identifier", identifier), helpers.String("error", err.Error()))
		identifier = uuid.New().String()
	}

	if networkEvent.PktType == networkmanager.OutgoingPktType {
		if ok := currEgressIdentifiersMap[identifier]; !ok {
			addToMap(egressIdentifiersMap, identifier, portIdentifier, neighborEntry)
		}
	} else {
		if ok := currIngressIdentifiersMap[identifier]; !ok {
			addToMap(ingressIdentifiersMap, identifier, portIdentifier, neighborEntry)
		}
	}

}

// addToMap adds neighborEntry to identifiersMap, if identifier already exists, it will add the ports to the existing entry
func addToMap(identifiersMap map[string]v1beta1.NetworkNeighbor, identifier string, portIdentifier string, neighborEntry v1beta1.NetworkNeighbor) {
	if existingNeighborEntry, ok := identifiersMap[identifier]; ok {
		found := false
		for _, port := range existingNeighborEntry.Ports {
			if port.Name == portIdentifier {
				found = true
				break
			}
		}
		if !found {
			neighborEntry.Ports = append(existingNeighborEntry.Ports, neighborEntry.Ports...)
		}
	}
	neighborEntry.Identifier = identifier
	identifiersMap[identifier] = neighborEntry
}

func (am *NetworkManager) handleServiceWithNoSelectors(networkEvent networkmanager.NetworkEvent, egressIdentifiersMap map[string]v1beta1.NetworkNeighbor, ingressIdentifiersMap map[string]v1beta1.NetworkNeighbor) error {

	// retrieve endpoint
	endpoints, err := am.k8sClient.GetWorkload(networkEvent.Destination.Namespace, "Endpoint", networkEvent.Destination.Name)
	if err != nil {
		return err
	}

	endpointsMap := endpoints.GetObject()

	endpointsBytes, err := json.Marshal(endpointsMap)
	if err != nil {
		return err
	}

	decoder := serializer.NewCodecFactory(scheme.Scheme).UniversalDecoder()
	obj := &v1.Endpoints{}

	if err = runtime.DecodeInto(decoder, endpointsBytes, obj); err != nil {
		return err
	}

	// for each IP in the endpoint, generate a neighborEntry with its ports
	for _, subset := range obj.Subsets {
		for _, address := range subset.Addresses {
			neighborEntry := v1beta1.NetworkNeighbor{
				IPAddress: address.IP,
				Type:      networkmanager.InternalTrafficType,
			}
			for _, ports := range subset.Ports {
				neighborEntry.Ports = append(neighborEntry.Ports, v1beta1.NetworkPort{
					Protocol: v1beta1.Protocol(ports.Protocol),
					Port:     ptr.To(ports.Port),
					Name:     networkmanager.GeneratePortIdentifier(string(ports.Protocol), ports.Port),
				})
			}

			identifier, err := utils.GenerateNeighborsIdentifier(neighborEntry)
			if err != nil {
				identifier = uuid.New().String()
			}
			neighborEntry.Identifier = identifier

			if networkEvent.PktType == networkmanager.OutgoingPktType {
				egressIdentifiersMap[identifier] = neighborEntry
			} else {
				ingressIdentifiersMap[identifier] = neighborEntry
			}
		}
	}

	return nil
}
func (am *NetworkManager) waitForContainer(k8sContainerID string) error {
	if am.removedContainers.Contains(k8sContainerID) {
		return fmt.Errorf("container %s has been removed", k8sContainerID)
	}
	return backoff.Retry(func() error {
		if am.trackedContainers.Contains(k8sContainerID) {
			return nil
		}
		return fmt.Errorf("container %s not found", k8sContainerID)
	}, backoff.NewExponentialBackOff())
}
