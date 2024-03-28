package networkmanager

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"node-agent/pkg/config"
	"node-agent/pkg/dnsmanager"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/storage"
	"node-agent/pkg/utils"
	"strings"
	"time"

	"github.com/armosec/utils-k8s-go/wlid"
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

const (
	internalTrafficType = "internal"
	externalTrafficType = "external"
	hostPktType         = "HOST"
	outgoingPktType     = "OUTGOING"
)

type NetworkManager struct {
	cfg                           config.Config
	ctx                           context.Context
	k8sClient                     k8sclient.K8sClientInterface
	storageClient                 storage.StorageClient
	containerAndPodToWLIDMap      maps.SafeMap[string, string]
	containerAndPodToEventsMap    maps.SafeMap[string, mapset.Set[NetworkEvent]]
	containerAndPodToDroppedEvent maps.SafeMap[string, bool]
	clusterName                   string
	watchedContainerChannels      maps.SafeMap[string, chan error] // key is ContainerID
	dnsResolverClient             dnsmanager.DNSResolver
	status                        string
	preRunningContainerIDs        mapset.Set[string]
}

var _ NetworkManagerClient = (*NetworkManager)(nil)

func CreateNetworkManager(ctx context.Context, cfg config.Config, k8sClient k8sclient.K8sClientInterface, storageClient storage.StorageClient, clusterName string, dnsResolverClient dnsmanager.DNSResolver, preRunningContainerIDs mapset.Set[string]) *NetworkManager {
	return &NetworkManager{
		cfg:                    cfg,
		ctx:                    ctx,
		k8sClient:              k8sClient,
		storageClient:          storageClient,
		clusterName:            clusterName,
		dnsResolverClient:      dnsResolverClient,
		preRunningContainerIDs: preRunningContainerIDs,
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

		// stop monitoring after MaxSniffingTime
		time.AfterFunc(am.cfg.MaxSniffingTime, func() {
			event := containercollection.PubSubEvent{
				Timestamp: time.Now().Format(time.RFC3339),
				Type:      containercollection.EventTypeRemoveContainer,
				Container: notif.Container,
			}
			am.ContainerCallback(event)
		})

	case containercollection.EventTypeRemoveContainer:
		channel := am.watchedContainerChannels.Get(notif.Container.Runtime.ContainerID)
		if channel != nil {
			channel <- utils.ContainerHasTerminatedError
		}
		am.watchedContainerChannels.Delete(notif.Container.Runtime.ContainerID)
	}
}

func (am *NetworkManager) ReportDroppedEvent(containerID string, event tracernetworktype.Event) {
	am.containerAndPodToDroppedEvent.Set(containerID+event.K8s.PodName, true)
}

func (am *NetworkManager) ReportNetworkEvent(containerID string, event tracernetworktype.Event) {

	if !am.isValidEvent(event) {
		return
	}

	networkEvent := &NetworkEvent{
		Port:     event.Port,
		Protocol: event.Proto,
		PktType:  event.PktType,
		Destination: Destination{
			Namespace: event.DstEndpoint.Namespace,
			Name:      event.DstEndpoint.Name,
			Kind:      EndpointKind(event.DstEndpoint.Kind),
			IPAddress: event.DstEndpoint.Addr,
		},
	}
	networkEvent.SetPodLabels(event.PodLabels)
	networkEvent.SetDestinationPodLabels(event.DstEndpoint.PodLabels)

	networkEventsSet := am.containerAndPodToEventsMap.Get(containerID + event.K8s.PodName)
	if am.containerAndPodToEventsMap.Get(containerID+event.K8s.PodName) == nil {
		networkEventsSet = mapset.NewSet[NetworkEvent]()
	}
	networkEventsSet.Add(*networkEvent)
	am.containerAndPodToEventsMap.Set(containerID+event.K8s.PodName, networkEventsSet)
}

// isValidEvent checks if the event is a valid event that should be saved
func (am *NetworkManager) isValidEvent(event tracernetworktype.Event) bool {
	// unknown type, shouldn't happen
	if event.PktType != hostPktType && event.PktType != outgoingPktType {
		logger.L().Debug("NetworkManager - pktType is not HOST or OUTGOING", helpers.Interface("event", event))
		return false
	}

	// ignore localhost
	if event.PktType == hostPktType && event.PodHostIP == event.DstEndpoint.Addr {
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

	// check if network neighbor CRD exists
	networkNeighbors, err := am.storageClient.GetNetworkNeighbors(parentWL.GetNamespace(), generateNetworkNeighborsNameFromWorkload(parentWL))
	if err != nil {
		if !strings.Contains(err.Error(), "not found") {
			logger.L().Warning("NetworkManager - failed to get network neighbor", helpers.String("reason", err.Error()), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
		} else {
			// network neighbor not found, create new one
			newNetworkNeighbors := generateNetworkNeighborsCRD(parentWL, selector, am.clusterName)
			if err = am.storageClient.CreateNetworkNeighbors(newNetworkNeighbors, parentWL.GetNamespace()); err != nil {
				logger.L().Warning("NetworkManager - failed to create network neighbor", helpers.String("reason", err.Error()), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
			} else {
				// set to initializing only if create was successful
				am.status = helpersv1.Initializing
				logger.L().Debug("NetworkManager - initializing", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
			}
		}
	} else {
		// CRD found, update labels
		networkNeighbors.Spec.LabelSelector = *selector
		am.status = networkNeighbors.GetAnnotations()[helpersv1.StatusMetadataKey]
		if err = am.storageClient.PatchNetworkNeighborsMatchLabels(networkNeighbors.GetName(), networkNeighbors.GetNamespace(), networkNeighbors); err != nil {
			logger.L().Warning("NetworkManager - failed to update network neighbor labels", helpers.String("reason", err.Error()), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
		}
		logger.L().Debug("NetworkManager - updated network neighbor labels", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
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
	am.containerAndPodToWLIDMap.Delete(container.Runtime.ContainerID + container.K8s.PodName)
	am.containerAndPodToEventsMap.Delete(container.Runtime.ContainerID + container.K8s.PodName)
	am.containerAndPodToDroppedEvent.Delete(container.Runtime.ContainerID + container.K8s.PodName)
	am.watchedContainerChannels.Delete(container.Runtime.ContainerID)
}

func (am *NetworkManager) monitorContainer(ctx context.Context, container *containercollection.Container, watchedContainer *utils.WatchedContainerData) error {
	for {
		select {
		case <-watchedContainer.UpdateDataTicker.C:
			// adjust ticker after first tick
			if !watchedContainer.InitialDelayExpired {
				watchedContainer.InitialDelayExpired = true
				watchedContainer.UpdateDataTicker.Reset(am.cfg.UpdateDataPeriod)
			}

			am.handleNetworkEvents(ctx, container, watchedContainer)
		case err := <-watchedContainer.SyncChannel:
			switch {
			case errors.Is(err, utils.ContainerHasTerminatedError):
				am.handleNetworkEvents(ctx, container, watchedContainer)
				return nil
			}
		}
	}
}

// handleNetworkEvents retrieves network events from map, generate entries for CRD and sends a PATCH command to update them
func (am *NetworkManager) handleNetworkEvents(_ context.Context, container *containercollection.Container, watchedContainer *utils.WatchedContainerData) {
	// retrieve parent WL from internal map
	parentWlid := am.containerAndPodToWLIDMap.Get(container.Runtime.ContainerID + container.K8s.PodName)
	if parentWlid == "" {
		logger.L().Warning("NetworkManager - failed to get parent wlid from map", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("pod name", container.K8s.PodName))
		return
	}

	name := generateNetworkNeighborsNameFromWlid(parentWlid)
	namespace := wlid.GetNamespaceFromWlid(parentWlid)
	networkNeighborsExists := false
	networkNeighbors, err := am.storageClient.GetNetworkNeighbors(namespace, name)
	if err != nil {
		if strings.Contains(err.Error(), "the server is currently unable to handle the request") {
			logger.L().Warning("NetworkManager - failed to update network neighbor", helpers.String("reason", err.Error()), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", watchedContainer.K8sContainerID))
			return
		}
	}
	if err == nil {
		networkNeighborsExists = true
	}

	if hadDroppedEvents := am.containerAndPodToDroppedEvent.Get(container.Runtime.ContainerID + container.K8s.PodName); hadDroppedEvents {
		am.status = helpersv1.MissingRuntime
	}

	networkEvents := am.containerAndPodToEventsMap.Get(container.Runtime.ContainerID + container.K8s.PodName)
	// no events to handle
	if networkEvents == nil {
		if networkNeighborsExists {
			// update status to ready
			if networkNeighbors.GetAnnotations()[helpersv1.StatusMetadataKey] == helpersv1.Initializing {
				// if we are in initializing state, we need to update the CRD to ready
				if err := am.storageClient.PatchNetworkNeighborsIngressAndEgress(name, namespace, &v1beta1.NetworkNeighbors{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							helpersv1.StatusMetadataKey: helpersv1.Ready,
						},
					},
				}); err != nil {
					logger.L().Warning("NetworkManager - failed to patch network neighbor status", helpers.String("reason", err.Error()), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", watchedContainer.K8sContainerID))
				} else {
					logger.L().Debug("NetworkManager - status updated to ready", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", watchedContainer.K8sContainerID))
				}
			}
		}
		return
	}
	// TODO: dns enrichment

	// update CRD based on events
	networkNeighborsSpec := am.generateNetworkNeighborsEntries(container.K8s.Namespace, networkEvents, networkNeighbors.Spec)

	if networkNeighborsExists {
		// patch only if there are changes
		if len(networkNeighborsSpec.Egress) > 0 || len(networkNeighborsSpec.Ingress) > 0 {
			// send PATCH command using entries generated from events
			nn := &v1beta1.NetworkNeighbors{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						helpersv1.StatusMetadataKey: helpersv1.Ready,
					},
				},
				Spec: networkNeighborsSpec,
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
		newNetworkNeighbors := generateNetworkNeighborsCRD(parentWL, selector, am.clusterName)

		// update spec and annotations
		networkNeighborsSpec.LabelSelector = *selector
		newNetworkNeighbors.Spec = networkNeighborsSpec
		newNetworkNeighbors.Annotations[helpersv1.StatusMetadataKey] = helpersv1.Ready

		logger.L().Debug("NetworkManager - creating network neighbor", helpers.Interface("labels", selector), helpers.String("container ID", container.Runtime.ContainerID), helpers.Interface("labels", newNetworkNeighbors.Spec.LabelSelector))

		if err = am.storageClient.CreateNetworkNeighbors(newNetworkNeighbors, parentWL.GetNamespace()); err != nil {
			logger.L().Warning("NetworkManager - failed to create network neighbor", helpers.String("reason", err.Error()), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("parent wlid", parentWlid))
			return
		}
		logger.L().Debug("NetworkManager - created network neighbor", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", watchedContainer.K8sContainerID))
	}

	// remove events from map
	am.containerAndPodToEventsMap.Delete(container.Runtime.ContainerID + container.K8s.PodName)
}
func (am *NetworkManager) generateNetworkNeighborsEntries(namespace string, networkEvents mapset.Set[NetworkEvent], currSpec v1beta1.NetworkNeighborsSpec) v1beta1.NetworkNeighborsSpec {
	var networkNeighborsSpec v1beta1.NetworkNeighborsSpec

	// auxiliary maps to avoid duplicates
	ingressIdentifiersMap := make(map[string]v1beta1.NetworkNeighbor)
	egressIdentifiersMap := make(map[string]v1beta1.NetworkNeighbor)

	// auxiliary maps to avoid duplicates
	currIngressIdentifiersMap := make(map[string]bool)
	currEgressIdentifiersMap := make(map[string]bool)

	for i := range currSpec.Egress {
		if identifier, err := generateNeighborsIdentifier(currSpec.Egress[i]); err == nil {
			currEgressIdentifiersMap[identifier] = true
		}
	}
	for i := range currSpec.Ingress {
		if identifier, err := generateNeighborsIdentifier(currSpec.Ingress[i]); err == nil {
			currIngressIdentifiersMap[identifier] = true
		}
	}

	networkEventsIterator := networkEvents.Iterator()
	if networkEventsIterator == nil {
		return networkNeighborsSpec
	}

	for networkEvent := range networkEventsIterator.C {
		var neighborEntry v1beta1.NetworkNeighbor

		if networkEvent.Destination.Kind == EndpointKindPod {
			// for Pods we need to remove the default labels
			neighborEntry.PodSelector = &metav1.LabelSelector{
				MatchLabels: filterLabels(networkEvent.GetDestinationPodLabels()),
			}

			if namespaceLabels := getNamespaceMatchLabels(networkEvent.Destination.Namespace, namespace); namespaceLabels != nil {
				neighborEntry.NamespaceSelector = &metav1.LabelSelector{
					MatchLabels: namespaceLabels,
				}
			}

		} else if networkEvent.Destination.Kind == EndpointKindService {
			// for service, we need to retrieve it and use its selector
			svc, err := am.k8sClient.GetWorkload(networkEvent.Destination.Namespace, "Service", networkEvent.Destination.Name)
			if err != nil {
				logger.L().Warning("failed to get service", helpers.String("reason", err.Error()), helpers.String("service name", networkEvent.Destination.Name))
				continue
			}

			selector := svc.GetServiceSelector()
			if len(selector) == 0 {
				if err = am.handleServiceWithNoSelectors(svc, networkEvent, egressIdentifiersMap, ingressIdentifiersMap); err != nil {
					logger.L().Warning("failed to handle service with no selectors", helpers.String("reason", err.Error()), helpers.String("service name", networkEvent.Destination.Name))
				}
				continue
			} else {
				neighborEntry.PodSelector = &metav1.LabelSelector{
					MatchLabels: selector,
				}
				if namespaceLabels := getNamespaceMatchLabels(networkEvent.Destination.Namespace, namespace); namespaceLabels != nil {
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
func saveNeighborEntry(networkEvent NetworkEvent, neighborEntry v1beta1.NetworkNeighbor, egressIdentifiersMap, ingressIdentifiersMap map[string]v1beta1.NetworkNeighbor, currEgressIdentifiersMap, currIngressIdentifiersMap map[string]bool) {

	portIdentifier := generatePortIdentifierFromEvent(networkEvent)

	neighborEntry.Ports = []v1beta1.NetworkPort{
		{
			Protocol: v1beta1.Protocol(networkEvent.Protocol),
			Port:     ptr.To(int32(networkEvent.Port)),
			Name:     portIdentifier,
		}}

	neighborEntry.Type = internalTrafficType
	if neighborEntry.NamespaceSelector == nil && neighborEntry.PodSelector == nil {
		neighborEntry.Type = externalTrafficType
	}

	// generate identifier for this neighborEntry
	identifier, err := generateNeighborsIdentifier(neighborEntry)
	if err != nil {
		// if we fail to hash, use a random identifier so at least we have the data on the crd
		logger.L().Debug("failed to hash identifier", helpers.String("identifier", identifier), helpers.String("error", err.Error()))
		identifier = uuid.New().String()
	}

	if networkEvent.PktType == outgoingPktType {
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

func (am *NetworkManager) handleServiceWithNoSelectors(svc workloadinterface.IWorkload, networkEvent NetworkEvent, egressIdentifiersMap map[string]v1beta1.NetworkNeighbor, ingressIdentifiersMap map[string]v1beta1.NetworkNeighbor) error {

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
				Type:      internalTrafficType,
			}
			for _, ports := range subset.Ports {
				neighborEntry.Ports = append(neighborEntry.Ports, v1beta1.NetworkPort{
					Protocol: v1beta1.Protocol(ports.Protocol),
					Port:     ptr.To(int32(ports.Port)),
					Name:     generatePortIdentifier(string(ports.Protocol), ports.Port),
				})
			}

			identifier, err := generateNeighborsIdentifier(neighborEntry)
			if err != nil {
				identifier = uuid.New().String()
			}
			neighborEntry.Identifier = identifier

			if networkEvent.PktType == outgoingPktType {
				egressIdentifiersMap[identifier] = neighborEntry
			} else {
				ingressIdentifiersMap[identifier] = neighborEntry
			}
		}
	}

	return nil
}

func getNamespaceMatchLabels(destinationNamespace, sourceNamespace string) map[string]string {
	if destinationNamespace != sourceNamespace {
		// from version 1.22, all namespace have the kubernetes.io/metadata.name label
		return map[string]string{
			"kubernetes.io/metadata.name": destinationNamespace,
		}
	}
	return nil
}

func generateNeighborsIdentifier(neighborEntry v1beta1.NetworkNeighbor) (string, error) {
	// identifier is hash of everything in egress except ports
	identifier := fmt.Sprintf("%s-%s-%s-%s-%s", neighborEntry.Type, neighborEntry.IPAddress, neighborEntry.DNS, neighborEntry.NamespaceSelector, neighborEntry.PodSelector)
	hash := sha256.New()
	_, err := hash.Write([]byte(identifier))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func generatePortIdentifierFromEvent(networkEvent NetworkEvent) string {
	return generatePortIdentifier(networkEvent.Protocol, int32(networkEvent.Port))
}

func generatePortIdentifier(protocol string, port int32) string {
	return fmt.Sprintf("%s-%d", protocol, port)
}
