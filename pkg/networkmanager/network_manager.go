package networkmanager

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"node-agent/pkg/config"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/storage"
	"node-agent/pkg/utils"
	"time"

	"github.com/armosec/utils-k8s-go/wlid"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
}

var _ NetworkManagerClient = (*NetworkManager)(nil)

func CreateNetworkManager(ctx context.Context, cfg config.Config, k8sClient k8sclient.K8sClientInterface, storageClient storage.StorageClient, clusterName string) (*NetworkManager, error) {
	return &NetworkManager{
		cfg:           cfg,
		ctx:           ctx,
		k8sClient:     k8sClient,
		storageClient: storageClient,
		clusterName:   clusterName,
	}, nil
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

func (am *NetworkManager) SaveNetworkEvent(containerID, podName string, networkEvent *NetworkEvent) {
	networkEventsSet := am.containerAndPodToEventsMap.Get(containerID + podName)
	if am.containerAndPodToEventsMap.Get(containerID+podName) == nil {
		networkEventsSet = mapset.NewSet[NetworkEvent]()
	}
	networkEventsSet.Add(*networkEvent)
	am.containerAndPodToEventsMap.Set(containerID+podName, networkEventsSet)
}

func (am *NetworkManager) handleContainerStarted(ctx context.Context, container *containercollection.Container, k8sContainerID string) {
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
		logger.L().Info("NetworkManager - failed to get selector", helpers.String("reason", err.Error()), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
		return
	}

	// TODO: check if it has network neighbor on storage
	// If yes, update labels
	am.patchNetworkNeighbor(nil)

	// If not, create CRD
	networkNeighbors := createNetworkNeighborsCRD(parentWL, selector)
	am.publishNetworkNeighbors(networkNeighbors)

	// save container + pod to wlid map
	am.containerAndPodToWLIDMap.Set(container.Runtime.ContainerID+container.K8s.PodName, parentWL.GenerateWlid(am.clusterName))

	if err := am.monitorContainer(ctx, container, watchedContainer); err != nil {
		logger.L().Info("NetworkManager - stop monitor on container", helpers.String("reason", err.Error()), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
	}

	am.handleContainerStopped(container)
}

// TODO: implement
func (am *NetworkManager) patchNetworkNeighbor(networkNeighbor *NetworkNeighbors) {
	// patch to storage
}

// TODO: implement
func (am *NetworkManager) publishNetworkNeighbors(networkNeighbor *NetworkNeighbors) {
	// publish to storage
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

func (am *NetworkManager) handleContainerStopped(container *containercollection.Container) {
	// clean up
	am.containerAndPodToWLIDMap.Delete(container.Runtime.ContainerID + container.K8s.PodName)
	am.containerAndPodToEventsMap.Delete(container.Runtime.ContainerID + container.K8s.PodName)
	am.watchedContainerChannels.Delete(container.Runtime.ContainerID)
}

// TODO: implement
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

func (am *NetworkManager) handleNetworkEvents(ctx context.Context, container *containercollection.Container, watchedContainer *utils.WatchedContainerData) {
	networkEvents := am.containerAndPodToEventsMap.Get(container.Runtime.ContainerID + container.K8s.PodName)
	if networkEvents == nil {
		// no events to handle
		return
	}

	// TODO: dns enrichment

	// update CRD based on events
	parentWlid := am.containerAndPodToWLIDMap.Get(container.Runtime.ContainerID + container.K8s.PodName)

	namespace := wlid.GetNamespaceFromWlid(parentWlid)
	kind := wlid.GetKindFromWlid(parentWlid)
	name := wlid.GetNameFromWlid(parentWlid)
	// TODO: use it to retrieve CRD
	fmt.Printf("namespace: %s, kind: %s, name: %s\n", namespace, kind, name)

	networkEntries := generateNetworkNeighborsEntries(container, networkEvents)

	//TODO: issue patch command
	networkEntriesMarshalled, err := json.Marshal(networkEntries)
	if err != nil {
		logger.L().Error("failed to marshal network entries", helpers.Error(err))
	}

	// TODO: remove
	fmt.Println(string(networkEntriesMarshalled))

	// clear event
	am.containerAndPodToEventsMap.Delete(container.Runtime.ContainerID + container.K8s.PodName)
}

func generateNetworkNeighborsEntries(container *containercollection.Container, networkEvents mapset.Set[NetworkEvent]) []NeighborEntry {
	var neighborEntries []NeighborEntry

	networkEventsIterator := networkEvents.Iterator()
	if networkEventsIterator == nil {
		return neighborEntries
	}

	for networkEvent := range networkEventsIterator.C {
		var neighborEntry NeighborEntry

		if networkEvent.PktType == "HOST" {
			neighborEntry.Type = "internal"
		} else if networkEvent.PktType == "OUTGOING" {
			neighborEntry.Type = "external"
		}

		if networkEvent.Destination.Kind == EndpointKindPod {
			neighborEntry.PodSelector = &metav1.LabelSelector{
				MatchLabels: filterLabels(networkEvent.GetDestinationPodLabels()),
			}
			if networkEvent.Destination.Namespace != container.K8s.Namespace {
				neighborEntry.NamespaceSelector = &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"kubernetes.io/metadata.name": networkEvent.Destination.Namespace,
					},
				}
			}
		} else if networkEvent.Destination.Kind == EndpointKindService {

			neighborEntry.PodSelector = &metav1.LabelSelector{
				MatchLabels: networkEvent.GetDestinationPodLabels(),
			}
			if networkEvent.Destination.Namespace != container.K8s.Namespace {
				neighborEntry.NamespaceSelector = &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"kubernetes.io/metadata.name": networkEvent.Destination.Namespace,
					},
				}
			}
		} else if networkEvent.Destination.Kind == EndpointKindRaw {
			if networkEvent.Destination.IPAddress == "127.0.0.1" {
				// No need to generate for localhost
				continue
			}
			neighborEntry.IPAddress = networkEvent.Destination.IPAddress
		}

		neighborEntry.Ports = []Port{
			{
				Protocol: networkEvent.Protocol,
				Port:     networkEvent.Port,
				Name:     fmt.Sprintf("%s-%d", networkEvent.Protocol, networkEvent.Port),
			}}

		// identifier is hash of everything in egress except ports
		identifier := fmt.Sprintf("%s-%s-%s-%s-%s", neighborEntry.Type, neighborEntry.IPAddress, neighborEntry.DNS, neighborEntry.NamespaceSelector, neighborEntry.PodSelector)
		hash := sha256.New()

		hash.Write([]byte(identifier))

		neighborEntry.Identifier = fmt.Sprintf("%x", hash.Sum(nil))

		neighborEntries = append(neighborEntries, neighborEntry)
	}

	return neighborEntries
}
