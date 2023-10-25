package networkmanager

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"node-agent/pkg/config"
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
	instanceidhandlerV1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

type NetworkManager struct {
	cfg                        config.Config
	ctx                        context.Context
	k8sClient                  k8sclient.K8sClientInterface
	storageClient              storage.StorageClient
	containerAndPodToWLIDMap   maps.SafeMap[string, string]
	containerAndPodToEventsMap maps.SafeMap[string, mapset.Set[NetworkEvent]] // TODO: change it to set
	clusterName                string
	watchedContainerChannels   maps.SafeMap[string, chan error] // key is ContainerID
	ignoredSubNet              *net.IPNet
}

var _ NetworkManagerClient = (*NetworkManager)(nil)

func CreateNetworkManager(ctx context.Context, cfg config.Config, k8sClient k8sclient.K8sClientInterface, storageClient storage.StorageClient, clusterName string) *NetworkManager {
	ignoreNetwork := "169.254.0.2/16"
	_, ignoreNet, err := net.ParseCIDR(ignoreNetwork)
	if err != nil {
		logger.L().Error("failed to parse CIDR", helpers.String("CIDR", ignoreNetwork))
	}

	return &NetworkManager{
		cfg:           cfg,
		ctx:           ctx,
		k8sClient:     k8sClient,
		storageClient: storageClient,
		clusterName:   clusterName,
		ignoredSubNet: ignoreNet,
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
		am.watchedContainerChannels.Delete(notif.Container.Runtime.ContainerID)
	}
}

func (am *NetworkManager) SaveNetworkEvent(containerID, podName string, event tracernetworktype.Event) {

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

	networkEventsSet := am.containerAndPodToEventsMap.Get(containerID + podName)
	if am.containerAndPodToEventsMap.Get(containerID+podName) == nil {
		networkEventsSet = mapset.NewSet[NetworkEvent]()
	}
	networkEventsSet.Add(*networkEvent)
	am.containerAndPodToEventsMap.Set(containerID+podName, networkEventsSet)

}

func (am *NetworkManager) isValidEvent(event tracernetworktype.Event) bool {
	if event.PktType != "HOST" && event.PktType != "OUTGOING" {
		logger.L().Debug("NetworkManager - pktType is not HOST or OUTGOING", helpers.Interface("event", event))
		return false
	}

	if event.PktType == "HOST" && event.PodHostIP == event.DstEndpoint.Addr {
		return false
	}

	if event.K8s.HostNetwork {
		return false
	}

	if am.ignoredSubNet.Contains(net.ParseIP(event.DstEndpoint.Addr)) {
		return false
	}
	return true
}

func (am *NetworkManager) handleContainerStarted(ctx context.Context, container *containercollection.Container, k8sContainerID string) {
	ctx, span := otel.Tracer("").Start(ctx, "NetworkManager.handleContainerStarted")
	defer span.End()

	logger.L().Debug("NetworkManager - handleContainerStarted", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))

	watchedContainer := &utils.WatchedContainerData{
		ContainerID:                              container.Runtime.ContainerID,
		UpdateDataTicker:                         time.NewTicker(am.cfg.InitialDelay),
		SyncChannel:                              make(chan error, 10),
		K8sContainerID:                           k8sContainerID,
		RelevantRealtimeFilesByPackageSourceInfo: map[string]*utils.PackageSourceInfoData{},
		RelevantRealtimeFilesBySPDXIdentifier:    map[v1beta1.ElementID]bool{},
	}
	am.watchedContainerChannels.Set(watchedContainer.ContainerID, watchedContainer.SyncChannel)

	// retrieve parent WL
	parentWL, err := am.getParentWorkloadFromContainer(container)
	if err != nil {
		logger.L().Info("NetworkManager - failed to get parent workload", helpers.String("reason", err.Error()), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
		return
	}

	selector, err := parentWL.GetSelector()
	if err != nil {
		// if we get not selector, we can't create/update network neighbor
		logger.L().Info("NetworkManager - failed to get selector", helpers.String("reason", err.Error()), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
		return
	}
	if selector == nil {
		// if we get not selector, we can't create/update network neighbor
		logger.L().Info("NetworkManager - selector is nil", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
		return
	}

	// check if network neighbor CRD exists
	networkNeighbors, err := am.storageClient.GetNetworkNeighbors(parentWL.GetNamespace(), generateNetworkNeighborsNameFromWorkload(parentWL))
	if err != nil {
		if !strings.Contains(err.Error(), "not found") {
			logger.L().Info("NetworkManager - failed to get network neighbor", helpers.String("reason", err.Error()), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
		} else {
			// network neighbor not found, create new one
			newNetworkNeighbors := generateNetworkNeighborsCRD(parentWL, selector)
			if err = am.storageClient.CreateNetworkNeighbors(newNetworkNeighbors, parentWL.GetNamespace()); err != nil {
				logger.L().Info("NetworkManager - failed to create network neighbor", helpers.String("reason", err.Error()), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
			}
			logger.L().Debug("NetworkManager - created network neighbor", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
		}
	} else {
		// CRD found, update labels
		networkNeighbors.Spec.LabelSelector = *selector
		if err = am.storageClient.PatchNetworkNeighborsMatchLabels(networkNeighbors.GetName(), networkNeighbors.GetNamespace(), networkNeighbors); err != nil {
			logger.L().Info("NetworkManager - failed to update network neighbor", helpers.String("reason", err.Error()), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
		}
		logger.L().Debug("NetworkManager - updated network neighbor", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
	}

	// save container + pod to wlid map
	am.containerAndPodToWLIDMap.Set(container.Runtime.ContainerID+container.K8s.PodName, parentWL.GenerateWlid(am.clusterName))

	if err := am.monitorContainer(ctx, container, watchedContainer); err != nil {
		logger.L().Info("NetworkManager - stop monitor on container", helpers.String("reason", err.Error()), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
	}

	am.deleteResources(container)
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
				logger.L().Debug("NetworkManager - container has terminated", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", watchedContainer.K8sContainerID))
				am.handleNetworkEvents(ctx, container, watchedContainer)
				return nil
			}
		}
	}
}

// handleNetworkEvents retrieves network events from map, generate entries for CRD and sends a PATCH command to update them
func (am *NetworkManager) handleNetworkEvents(ctx context.Context, container *containercollection.Container, watchedContainer *utils.WatchedContainerData) {

	networkEvents := am.containerAndPodToEventsMap.Get(container.Runtime.ContainerID + container.K8s.PodName)
	if networkEvents == nil {
		// no events to handle
		logger.L().Debug("NetworkManager - no events to handle", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", watchedContainer.K8sContainerID))
		return
	}
	// TODO: dns enrichment

	// update CRD based on events

	// retrieve parent WL from internal map
	parentWlid := am.containerAndPodToWLIDMap.Get(container.Runtime.ContainerID + container.K8s.PodName)
	if parentWlid == "" {
		logger.L().Error("failed to get parent wlid from map", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("pod name", container.K8s.PodName))
		return
	}

	networkNeighborsSpec := am.generateNetworkNeighborsEntries(container.K8s.Namespace, networkEvents)
	// send PATCH command using entries generated from events
	if err := am.storageClient.PatchNetworkNeighborsIngressAndEgress(generateNetworkNeighborsNameFromWlid(parentWlid), wlid.GetNamespaceFromWlid(parentWlid), &v1beta1.NetworkNeighbors{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				instanceidhandlerV1.StatusMetadataKey: completeStatus,
			},
		},
		Spec: networkNeighborsSpec,
	}); err != nil {
		logger.L().Error("failed to update network neighbor", helpers.String("reason", err.Error()), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", watchedContainer.K8sContainerID))
		return
	}
	logger.L().Debug("NetworkManager - updated network neighbor", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", watchedContainer.K8sContainerID))

	// remove events from map
	am.containerAndPodToEventsMap.Delete(container.Runtime.ContainerID + container.K8s.PodName)
}

func (am *NetworkManager) generateNetworkNeighborsEntries(namespace string, networkEvents mapset.Set[NetworkEvent]) v1beta1.NetworkNeighborsSpec {

	defer func() {
		if err := recover(); err != nil { //catch
			logger.L().Error("panic", helpers.String("error", err.(error).Error()))
		}
	}()

	var networkNeighborsSpec v1beta1.NetworkNeighborsSpec

	logger.L().Debug("NetworkManager - generateNetworkNeighborsEntries start")

	// auxiliary maps to avoid duplicates
	ingressIdentifiersMap := make(map[string]v1beta1.NetworkNeighbor)
	egressIdentifiersMap := make(map[string]v1beta1.NetworkNeighbor)

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
			logger.L().Debug("NetworkManager - generateNetworkNeighborsEntries - service")

			svc, err := am.k8sClient.GetWorkload(networkEvent.Destination.Namespace, "Service", networkEvent.Destination.Name)
			if err != nil {
				logger.L().Error("failed to get service", helpers.String("reason", err.Error()), helpers.String("service name", networkEvent.Destination.Name))
				continue
			}
			logger.L().Debug("NetworkManager - generateNetworkNeighborsEntries - retrieved service")

			selector, err := svc.GetSelector()
			if err != nil {
				logger.L().Error("failed to get selector", helpers.String("reason", err.Error()), helpers.String("service name", networkEvent.Destination.Name))
				continue
			}
			logger.L().Debug("NetworkManager - generateNetworkNeighborsEntries - retrieved selector")

			neighborEntry.PodSelector = selector

			logger.L().Debug("NetworkManager - generateNetworkNeighborsEntries - set selector")
			if namespaceLabels := getNamespaceMatchLabels(networkEvent.Destination.Namespace, namespace); namespaceLabels != nil {
				neighborEntry.NamespaceSelector = &metav1.LabelSelector{
					MatchLabels: namespaceLabels,
				}
			}
			logger.L().Debug("NetworkManager - generateNetworkNeighborsEntries - set getNamespaceMatchLabels")
		} else {
			if networkEvent.Destination.IPAddress == "127.0.0.1" {
				// No need to generate for localhost
				continue
			}
			neighborEntry.IPAddress = networkEvent.Destination.IPAddress
		}

		portIdentifier := generatePortIdentifier(networkEvent)
		logger.L().Debug("NetworkManager - generateNetworkNeighborsEntries - set generatePortIdentifier")

		neighborEntry.Ports = []v1beta1.NetworkPort{
			{
				Protocol: v1beta1.Protocol(networkEvent.Protocol),
				Port:     ptr.To(int32(networkEvent.Port)),
				Name:     portIdentifier,
			}}

		neighborEntry.Type = "internal"
		if len(networkEvent.GetDestinationPodLabels()) == 0 {
			neighborEntry.Type = "external"
		}

		// generate identifier for this neighborEntry
		identifier, err := generateNeighborsIdentifier(neighborEntry)
		logger.L().Debug("NetworkManager - generateNetworkNeighborsEntries - set generateNeighborsIdentifier")
		if err != nil {
			// if we fail to hash, use a random identifier so at least we have the data on the crd
			logger.L().Error("failed to hash identifier", helpers.String("identifier", identifier), helpers.String("error", err.Error()))
			identifier = uuid.New().String()
		}

		logger.L().Debug("NetworkManager - generateNetworkNeighborsEntries -  start loop", helpers.String("pktType", networkEvent.PktType))

		if networkEvent.PktType == "OUTGOING" {
			if existingNeighborEntry, ok := egressIdentifiersMap[identifier]; ok {
				logger.L().Debug("NetworkManager - generateNetworkNeighborsEntries -  existingNeighborEntry", helpers.Interface("existingNeighborEntry", existingNeighborEntry))
				// if we already have this identifier, check if there is a new port
				for _, port := range existingNeighborEntry.Ports {
					logger.L().Debug("NetworkManager - generateNetworkNeighborsEntries -  port", helpers.Interface("port", port))
					if port.Name == portIdentifier {
						logger.L().Debug("NetworkManager - generateNetworkNeighborsEntries -  port already exists")
						// port already exists in neighborEntry.Ports...
						continue
					}
					// new port, add it to same entry
					logger.L().Debug("NetworkManager - generateNetworkNeighborsEntries -  existingNeighborEntry", helpers.Interface("neighborEntry", neighborEntry))
					neighborEntry.Ports = append(existingNeighborEntry.Ports, neighborEntry.Ports...)
				}
			}
			logger.L().Debug("NetworkManager - generateNetworkNeighborsEntries -  set map")
			neighborEntry.Identifier = identifier
			egressIdentifiersMap[identifier] = neighborEntry
			logger.L().Debug("NetworkManager - generateNetworkNeighborsEntries -  finish set map")
		} else {
			if existingNeighborEntry, ok := ingressIdentifiersMap[identifier]; ok {
				// if we already have this identifier, check if there is a new port
				for _, port := range existingNeighborEntry.Ports {
					if port.Name == portIdentifier {
						// port already exists in neighborEntry.Ports...
						continue
					}
					// new port, add it to same entry
					neighborEntry.Ports = append(existingNeighborEntry.Ports, neighborEntry.Ports...)
					break
				}
			}
			logger.L().Debug("NetworkManager - generateNetworkNeighborsEntries -  set map")
			neighborEntry.Identifier = identifier
			ingressIdentifiersMap[identifier] = neighborEntry
			logger.L().Debug("NetworkManager - generateNetworkNeighborsEntries -  finish set map")
		}

		logger.L().Debug("NetworkManager - generateNetworkNeighborsEntries -  finish loop")

	}

	logger.L().Debug("NetworkManager - generateNetworkNeighborsEntries -  add to obj")

	networkNeighborsSpec.Egress = make([]v1beta1.NetworkNeighbor, 0, len(egressIdentifiersMap))
	for _, neighborEntry := range egressIdentifiersMap {
		networkNeighborsSpec.Egress = append(networkNeighborsSpec.Egress, neighborEntry)
	}

	networkNeighborsSpec.Ingress = make([]v1beta1.NetworkNeighbor, 0, len(ingressIdentifiersMap))
	for _, neighborEntry := range ingressIdentifiersMap {
		networkNeighborsSpec.Ingress = append(networkNeighborsSpec.Ingress, neighborEntry)
	}

	logger.L().Debug("NetworkManager - generateNetworkNeighborsEntries finish")

	return networkNeighborsSpec
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

func generatePortIdentifier(networkEvent NetworkEvent) string {
	return fmt.Sprintf("%s-%d", networkEvent.Protocol, networkEvent.Port)
}
