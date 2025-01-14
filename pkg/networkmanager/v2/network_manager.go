package v2

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/armosec/utils-k8s-go/wlid"
	"github.com/cenkalti/backoff/v4"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/google/uuid"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/networkmanager"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	storageUtils "github.com/kubescape/storage/pkg/utils"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"istio.io/pkg/cache"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

type NetworkManager struct {
	cfg                      config.Config
	clusterName              string
	ctx                      context.Context
	containerMutexes         storageUtils.MapMutex[string]                                 // key is k8sContainerID
	trackedContainers        mapset.Set[string]                                            // key is k8sContainerID
	removedContainers        mapset.Set[string]                                            // key is k8sContainerID
	droppedEventsContainers  mapset.Set[string]                                            // key is k8sContainerID
	savedEvents              maps.SafeMap[string, cache.ExpiringCache]                     // key is k8sContainerID
	toSaveEvents             maps.SafeMap[string, mapset.Set[networkmanager.NetworkEvent]] // key is k8sContainerID
	watchedContainerChannels maps.SafeMap[string, chan error]                              // key is ContainerID
	k8sClient                k8sclient.K8sClientInterface
	k8sObjectCache           objectcache.K8sObjectCache
	storageClient            storage.StorageClient
	preRunningContainerIDs   mapset.Set[string]
	dnsResolverClient        dnsmanager.DNSResolver
}

var _ networkmanager.NetworkManagerClient = (*NetworkManager)(nil)

func CreateNetworkManager(ctx context.Context, cfg config.Config, clusterName string, k8sClient k8sclient.K8sClientInterface, storageClient storage.StorageClient, dnsResolverClient dnsmanager.DNSResolver, preRunningContainerIDs mapset.Set[string], k8sObjectCache objectcache.K8sObjectCache) *NetworkManager {
	return &NetworkManager{
		cfg:                     cfg,
		clusterName:             clusterName,
		ctx:                     ctx,
		dnsResolverClient:       dnsResolverClient,
		k8sClient:               k8sClient,
		k8sObjectCache:          k8sObjectCache,
		storageClient:           storageClient,
		containerMutexes:        storageUtils.NewMapMutex[string](),
		trackedContainers:       mapset.NewSet[string](),
		removedContainers:       mapset.NewSet[string](),
		droppedEventsContainers: mapset.NewSet[string](),
		preRunningContainerIDs:  preRunningContainerIDs,
	}
}

func (nm *NetworkManager) ensureInstanceID(container *containercollection.Container, watchedContainer *utils.WatchedContainerData) error {
	if watchedContainer.InstanceID != nil {
		return nil
	}
	wl, err := nm.k8sClient.GetWorkload(container.K8s.Namespace, "Pod", container.K8s.PodName)
	if err != nil {
		return fmt.Errorf("failed to get workload: %w", err)
	}
	pod := wl.(*workloadinterface.Workload)
	// fill container type, index and names
	if watchedContainer.ContainerType == utils.Unknown {
		if err := watchedContainer.SetContainerInfo(pod, container.K8s.ContainerName); err != nil {
			return fmt.Errorf("failed to set container info: %w", err)
		}
	}
	// get pod template hash
	watchedContainer.TemplateHash, _ = pod.GetLabel("pod-template-hash")
	// find parentWlid
	kind, name, err := nm.k8sClient.CalculateWorkloadParentRecursive(pod)
	if err != nil {
		return fmt.Errorf("failed to calculate workload parent: %w", err)
	}
	parentWorkload, err := nm.k8sClient.GetWorkload(pod.GetNamespace(), kind, name)
	if err != nil {
		return fmt.Errorf("failed to get parent workload: %w", err)
	}
	w := parentWorkload.(*workloadinterface.Workload)
	watchedContainer.Wlid = w.GenerateWlid(nm.clusterName)
	err = wlid.IsWlidValid(watchedContainer.Wlid)
	if err != nil {
		return fmt.Errorf("failed to validate WLID: %w", err)
	}
	watchedContainer.ParentResourceVersion = w.GetResourceVersion()
	// find parent selector
	selector, err := w.GetSelector()
	if err != nil {
		return fmt.Errorf("failed to get parentWL selector: %w", err)
	}
	watchedContainer.ParentWorkloadSelector = selector
	// find instanceID - this has to be the last one
	instanceIDs, err := instanceidhandler.GenerateInstanceID(pod)
	if err != nil {
		return fmt.Errorf("failed to generate instanceID: %w", err)
	}
	watchedContainer.InstanceID = instanceIDs[0]
	for i := range instanceIDs {
		if instanceIDs[i].GetContainerName() == container.K8s.ContainerName {
			watchedContainer.InstanceID = instanceIDs[i]
		}
	}
	return nil
}

func (nm *NetworkManager) deleteResources(watchedContainer *utils.WatchedContainerData) {
	// make sure we don't run deleteResources and saveProfile at the same time
	nm.containerMutexes.Lock(watchedContainer.K8sContainerID)
	defer nm.containerMutexes.Unlock(watchedContainer.K8sContainerID)
	nm.removedContainers.Add(watchedContainer.K8sContainerID)
	// delete resources
	watchedContainer.UpdateDataTicker.Stop()
	nm.trackedContainers.Remove(watchedContainer.K8sContainerID)
	nm.droppedEventsContainers.Remove(watchedContainer.K8sContainerID)
	nm.savedEvents.Delete(watchedContainer.K8sContainerID)
	nm.toSaveEvents.Delete(watchedContainer.K8sContainerID)
	nm.watchedContainerChannels.Delete(watchedContainer.ContainerID)
}

func (nm *NetworkManager) ContainerReachedMaxTime(containerID string) {
	if channel := nm.watchedContainerChannels.Get(containerID); channel != nil {
		channel <- utils.ContainerReachedMaxTime
	}
}

// isValidEvent checks if the event is a valid event that should be saved
func (nm *NetworkManager) isValidEvent(event tracernetworktype.Event) bool {
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

func (nm *NetworkManager) monitorContainer(ctx context.Context, container *containercollection.Container, watchedContainer *utils.WatchedContainerData) error {
	// set completion status & status as soon as we start monitoring the container
	if nm.preRunningContainerIDs.Contains(container.Runtime.ContainerID) {
		watchedContainer.SetCompletionStatus(utils.WatchedContainerCompletionStatusPartial)
	} else {
		watchedContainer.SetCompletionStatus(utils.WatchedContainerCompletionStatusFull)
	}
	watchedContainer.SetStatus(utils.WatchedContainerStatusInitializing)
	nm.saveNetworkEvents(ctx, watchedContainer, container.K8s.Namespace)

	for {
		select {
		case <-watchedContainer.UpdateDataTicker.C:
			// adjust ticker after first tick
			if !watchedContainer.InitialDelayExpired {
				watchedContainer.InitialDelayExpired = true
				watchedContainer.UpdateDataTicker.Reset(utils.AddJitter(nm.cfg.UpdateDataPeriod, nm.cfg.MaxJitterPercentage))
			}
			watchedContainer.SetStatus(utils.WatchedContainerStatusReady)
			nm.saveNetworkEvents(ctx, watchedContainer, container.K8s.Namespace)
		case err := <-watchedContainer.SyncChannel:
			switch {
			case errors.Is(err, utils.ContainerHasTerminatedError):
				// if exit code is 0 we set the status to completed
				if objectcache.GetTerminationExitCode(nm.k8sObjectCache, container.K8s.Namespace, container.K8s.PodName, container.K8s.ContainerName, container.Runtime.ContainerID) == 0 {
					watchedContainer.SetStatus(utils.WatchedContainerStatusCompleted)
				}
				nm.saveNetworkEvents(ctx, watchedContainer, container.K8s.Namespace)
				return err
			case errors.Is(err, utils.ContainerReachedMaxTime):
				watchedContainer.SetStatus(utils.WatchedContainerStatusCompleted)
				nm.saveNetworkEvents(ctx, watchedContainer, container.K8s.Namespace)
				return err
			case errors.Is(err, utils.ObjectCompleted):
				watchedContainer.SetStatus(utils.WatchedContainerStatusCompleted)
				return err
			case errors.Is(err, utils.TooLargeObjectError):
				watchedContainer.SetStatus(utils.WatchedContainerStatusTooLarge)
				return err
			}
		}
	}
}

func (nm *NetworkManager) saveNetworkEvents(ctx context.Context, watchedContainer *utils.WatchedContainerData, namespace string) {
	ctx, span := otel.Tracer("").Start(ctx, "NetworkManager.saveProfile")
	defer span.End()

	// make sure we don't run deleteResources and saveProfile at the same time
	nm.containerMutexes.Lock(watchedContainer.K8sContainerID)
	defer nm.containerMutexes.Unlock(watchedContainer.K8sContainerID)

	// verify the container hasn't already been deleted
	if !nm.trackedContainers.Contains(watchedContainer.K8sContainerID) {
		logger.L().Debug("NetworkManager - container isn't tracked, not saving profile",
			helpers.Int("container index", watchedContainer.ContainerIndex),
			helpers.String("container ID", watchedContainer.ContainerID),
			helpers.String("k8s workload", watchedContainer.K8sContainerID))
		return
	}

	if watchedContainer.InstanceID == nil {
		logger.L().Debug("NetworkManager - instanceID is nil",
			helpers.Int("container index", watchedContainer.ContainerIndex),
			helpers.String("container ID", watchedContainer.ContainerID),
			helpers.String("k8s workload", watchedContainer.K8sContainerID))
		return
	}

	// leave container name empty this way the "slug" will represent a workload
	slug, err := watchedContainer.InstanceID.GetSlug(true)
	if err != nil {
		logger.L().Ctx(ctx).Warning("NetworkManager - failed to get slug", helpers.Error(err),
			helpers.String("slug", slug),
			helpers.Int("container index", watchedContainer.ContainerIndex),
			helpers.String("container ID", watchedContainer.ContainerID),
			helpers.String("k8s workload", watchedContainer.K8sContainerID))
		return
	}

	// sleep for container index second to desynchronize the profiles saving
	time.Sleep(time.Duration(watchedContainer.ContainerIndex) * time.Second)

	if nm.droppedEventsContainers.ContainsOne(watchedContainer.K8sContainerID) {
		watchedContainer.SetStatus(utils.WatchedContainerStatusMissingRuntime)
	}

	// get pointer to events map from IG
	toSaveEvents := nm.toSaveEvents.Get(watchedContainer.K8sContainerID)
	// point IG to a new events map
	nm.toSaveEvents.Set(watchedContainer.K8sContainerID, mapset.NewSet[networkmanager.NetworkEvent]())
	// add to ingress and egress
	var ingress []v1beta1.NetworkNeighbor
	var egress []v1beta1.NetworkNeighbor
	for _, event := range toSaveEvents.ToSlice() {
		neighbor := nm.createNetworkNeighbor(event, namespace)
		if neighbor == nil {
			continue
		}
		if event.PktType == networkmanager.HostPktType {
			ingress = append(ingress, *neighbor)
		} else {
			egress = append(egress, *neighbor)
		}
	}

	// new activity
	// the process tries to use JSON patching to avoid conflicts between updates on the same object from different containers
	// 0. create both a patch and a new object
	// 1. try to apply the patch
	// 2a. the object doesn't exist - create the new object
	// 2b. the patch was invalid - get existing object to fix the patch
	// 3a. the object is missing its container slice - ADD one with the container profile at the right index
	// 3b. the object is missing the container profile - ADD the container profile at the right index
	// 3c. default - patch the container ourselves and REPLACE it at the right index
	if len(ingress) > 0 || len(egress) > 0 || watchedContainer.StatusUpdated() {
		// 0. calculate patch
		operations := utils.CreateNetworkPatchOperations(ingress, egress, watchedContainer.ContainerType.String(), watchedContainer.ContainerIndex)
		operations = utils.AppendStatusAnnotationPatchOperations(operations, watchedContainer)

		// 1. try to patch object
		var gotErr error
		if err := nm.storageClient.PatchNetworkNeighborhood(slug, namespace, operations, watchedContainer.SyncChannel); err != nil {
			if apierrors.IsNotFound(err) {
				// 2a. new object
				newObject := &v1beta1.NetworkNeighborhood{
					ObjectMeta: metav1.ObjectMeta{
						Name: slug,
						Annotations: map[string]string{
							helpersv1.WlidMetadataKey:       watchedContainer.Wlid,
							helpersv1.CompletionMetadataKey: string(watchedContainer.GetCompletionStatus()),
							helpersv1.StatusMetadataKey:     string(watchedContainer.GetStatus()),
						},
						Labels: utils.GetLabels(watchedContainer, true),
					},
					Spec: v1beta1.NetworkNeighborhoodSpec{
						LabelSelector: metav1.LabelSelector{
							MatchLabels:      watchedContainer.ParentWorkloadSelector.MatchLabels,
							MatchExpressions: watchedContainer.ParentWorkloadSelector.MatchExpressions,
						},
					},
				}
				addContainers := func(containers []v1beta1.NetworkNeighborhoodContainer, containerInfos []utils.ContainerInfo) []v1beta1.NetworkNeighborhoodContainer {
					for _, info := range containerInfos {
						containers = append(containers, v1beta1.NetworkNeighborhoodContainer{Name: info.Name})
					}
					return containers
				}
				newObject.Spec.Containers = addContainers(newObject.Spec.Containers, watchedContainer.ContainerInfos[utils.Container])
				newObject.Spec.InitContainers = addContainers(newObject.Spec.InitContainers, watchedContainer.ContainerInfos[utils.InitContainer])
				newObject.Spec.EphemeralContainers = addContainers(newObject.Spec.EphemeralContainers, watchedContainer.ContainerInfos[utils.EphemeralContainer])
				// enrich container
				newContainer := utils.GetNetworkNeighborhoodContainer(newObject, watchedContainer.ContainerType, watchedContainer.ContainerIndex)
				utils.EnrichNeighborhoodContainer(newContainer, ingress, egress)
				// try to create object
				if err := nm.storageClient.CreateNetworkNeighborhood(newObject, namespace); err != nil {
					gotErr = err
					logger.L().Ctx(ctx).Warning("NetworkManager - failed to create network neighborhood", helpers.Error(err),
						helpers.String("slug", slug),
						helpers.Int("container index", watchedContainer.ContainerIndex),
						helpers.String("container ID", watchedContainer.ContainerID),
						helpers.String("k8s workload", watchedContainer.K8sContainerID))
				}
			} else {
				logger.L().Debug("NetworkManager - failed to patch network neighborhood, will get existing one and adjust patch", helpers.Error(err),
					helpers.String("slug", slug),
					helpers.Int("container index", watchedContainer.ContainerIndex),
					helpers.String("container ID", watchedContainer.ContainerID),
					helpers.String("k8s workload", watchedContainer.K8sContainerID))
				// 2b. get existing object
				existingObject, err := nm.storageClient.GetNetworkNeighborhood(namespace, slug)
				if err != nil {
					gotErr = err
					logger.L().Ctx(ctx).Warning("NetworkManager - failed to get existing network neighborhood", helpers.Error(err),
						helpers.String("slug", slug),
						helpers.Int("container index", watchedContainer.ContainerIndex),
						helpers.String("container ID", watchedContainer.ContainerID),
						helpers.String("k8s workload", watchedContainer.K8sContainerID))
				} else {
					var replaceOperations []utils.PatchOperation
					containerNames := watchedContainer.ContainerInfos[watchedContainer.ContainerType]
					// check existing container
					existingContainer := utils.GetNetworkNeighborhoodContainer(existingObject, watchedContainer.ContainerType, watchedContainer.ContainerIndex)
					if existingContainer == nil {
						existingContainer = &v1beta1.NetworkNeighborhoodContainer{
							Name: containerNames[watchedContainer.ContainerIndex].Name,
						}
					}
					// update it
					utils.EnrichNeighborhoodContainer(existingContainer, ingress, egress)
					// get existing containers
					var existingContainers []v1beta1.NetworkNeighborhoodContainer
					if watchedContainer.ContainerType == utils.Container {
						existingContainers = existingObject.Spec.Containers
					} else if watchedContainer.ContainerType == utils.InitContainer {
						existingContainers = existingObject.Spec.InitContainers
					} else {
						existingContainers = existingObject.Spec.EphemeralContainers
					}
					// replace or add container using patch
					// 3a. ensure we have a container slice
					if existingContainers == nil {
						replaceOperations = append(replaceOperations, utils.PatchOperation{
							Op:    "add",
							Path:  fmt.Sprintf("/spec/%s", watchedContainer.ContainerType),
							Value: make([]v1beta1.NetworkNeighborhoodContainer, 0),
						})
					}
					// 3b. ensure the slice has all the containers
					for i := len(existingContainers); i < len(containerNames); i++ {
						replaceOperations = append(replaceOperations, utils.PatchOperation{
							Op:   "add",
							Path: fmt.Sprintf("/spec/%s/%d", watchedContainer.ContainerType, i),
							Value: v1beta1.NetworkNeighborhoodContainer{
								Name: containerNames[i].Name,
							},
						})
					}
					// 3c. replace the existing container at the right index
					replaceOperations = append(replaceOperations, utils.PatchOperation{
						Op:    "replace",
						Path:  fmt.Sprintf("/spec/%s/%d", watchedContainer.ContainerType, watchedContainer.ContainerIndex),
						Value: existingContainer,
					})

					replaceOperations = utils.AppendStatusAnnotationPatchOperations(replaceOperations, watchedContainer)

					if err := nm.storageClient.PatchNetworkNeighborhood(slug, namespace, replaceOperations, watchedContainer.SyncChannel); err != nil {
						gotErr = err
						logger.L().Ctx(ctx).Warning("NetworkManager - failed to patch network neighborhood", helpers.Error(err),
							helpers.String("slug", slug),
							helpers.Int("container index", watchedContainer.ContainerIndex),
							helpers.String("container ID", watchedContainer.ContainerID),
							helpers.String("k8s workload", watchedContainer.K8sContainerID))
					}
				}
			}
		}
		if gotErr != nil {
			// restore events
			nm.toSaveEvents.Get(watchedContainer.K8sContainerID).Append(toSaveEvents.ToSlice()...)
		} else {
			// for status updates to be tracked, we reset the update flag
			watchedContainer.ResetStatusUpdatedFlag()

			// record saved events
			savedEvents := nm.savedEvents.Get(watchedContainer.K8sContainerID)
			toSaveEvents.Each(func(event networkmanager.NetworkEvent) bool {
				savedEvents.Set(event, nil)
				return false
			})
			logger.L().Debug("NetworkManager - saved neighborhood",
				helpers.Int("events", toSaveEvents.Cardinality()),
				helpers.String("slug", slug),
				helpers.Int("container index", watchedContainer.ContainerIndex),
				helpers.String("container ID", watchedContainer.ContainerID),
				helpers.String("k8s workload", watchedContainer.K8sContainerID))
		}
	}
}

func (nm *NetworkManager) startNetworkMonitoring(ctx context.Context, container *containercollection.Container, k8sContainerID string) {
	ctx, span := otel.Tracer("").Start(ctx, "NetworkManager.startNetworkMonitoring")
	defer span.End()

	syncChannel := make(chan error, 10)
	nm.watchedContainerChannels.Set(container.Runtime.ContainerID, syncChannel)

	watchedContainer := &utils.WatchedContainerData{
		ContainerID:      container.Runtime.ContainerID,
		ImageID:          container.Runtime.ContainerImageDigest,
		ImageTag:         container.Runtime.ContainerImageName,
		UpdateDataTicker: time.NewTicker(utils.AddJitter(nm.cfg.InitialDelay, nm.cfg.MaxJitterPercentage)),
		SyncChannel:      syncChannel,
		K8sContainerID:   k8sContainerID,
		NsMntId:          container.Mntns,
	}

	// don't start monitoring until we have the instanceID - need to retry until the Pod is updated
	if err := backoff.Retry(func() error {
		return nm.ensureInstanceID(container, watchedContainer)
	}, backoff.NewExponentialBackOff()); err != nil {
		logger.L().Debug("NetworkManager - failed to ensure instanceID", helpers.Error(err),
			helpers.Int("container index", watchedContainer.ContainerIndex),
			helpers.String("container ID", watchedContainer.ContainerID),
			helpers.String("k8s workload", watchedContainer.K8sContainerID))
	}

	if err := nm.monitorContainer(ctx, container, watchedContainer); err != nil {
		logger.L().Debug("NetworkManager - stop monitor on container", helpers.String("reason", err.Error()),
			helpers.Int("container index", watchedContainer.ContainerIndex),
			helpers.String("container ID", watchedContainer.ContainerID),
			helpers.String("k8s workload", watchedContainer.K8sContainerID))
	}

	nm.deleteResources(watchedContainer)
}

func (nm *NetworkManager) waitForContainer(k8sContainerID string) error {
	if nm.removedContainers.Contains(k8sContainerID) {
		return fmt.Errorf("container %s has been removed", k8sContainerID)
	}
	return backoff.Retry(func() error {
		if nm.trackedContainers.Contains(k8sContainerID) {
			return nil
		}
		return fmt.Errorf("container %s not found", k8sContainerID)
	}, backoff.NewExponentialBackOff())
}

func (nm *NetworkManager) ContainerCallback(notif containercollection.PubSubEvent) {
	// check if the container should be ignored
	if nm.cfg.SkipNamespace(notif.Container.K8s.Namespace) {
		return
	}

	k8sContainerID := utils.CreateK8sContainerID(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.ContainerName)
	ctx, span := otel.Tracer("").Start(nm.ctx, "NetworkManager.ContainerCallback", trace.WithAttributes(attribute.String("containerID", notif.Container.Runtime.ContainerID), attribute.String("k8s workload", k8sContainerID)))
	defer span.End()

	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		if nm.watchedContainerChannels.Has(notif.Container.Runtime.ContainerID) {
			logger.L().Debug("NetworkManager - container already exist in memory",
				helpers.String("container ID", notif.Container.Runtime.ContainerID),
				helpers.String("k8s workload", k8sContainerID))
			return
		}
		nm.savedEvents.Set(k8sContainerID, cache.NewTTL(5*nm.cfg.UpdateDataPeriod, nm.cfg.UpdateDataPeriod))
		nm.toSaveEvents.Set(k8sContainerID, mapset.NewSet[networkmanager.NetworkEvent]())
		nm.removedContainers.Remove(k8sContainerID) // make sure container is not in the removed list
		nm.trackedContainers.Add(k8sContainerID)
		go nm.startNetworkMonitoring(ctx, notif.Container, k8sContainerID)
	case containercollection.EventTypeRemoveContainer:
		channel := nm.watchedContainerChannels.Get(notif.Container.Runtime.ContainerID)
		if channel != nil {
			channel <- utils.ContainerHasTerminatedError
		}
	}
}

func (nm *NetworkManager) ReportNetworkEvent(k8sContainerID string, event tracernetworktype.Event) {
	if err := nm.waitForContainer(k8sContainerID); err != nil {
		return
	}
	if !nm.isValidEvent(event) {
		return
	}

	networkEvent := networkmanager.NetworkEvent{
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

	// skip if we already saved this event
	if _, ok := nm.savedEvents.Get(k8sContainerID).Get(networkEvent); ok {
		return
	}
	nm.toSaveEvents.Get(k8sContainerID).Add(networkEvent)
}

func (nm *NetworkManager) ReportDroppedEvent(k8sContainerID string) {
	nm.droppedEventsContainers.Add(k8sContainerID)
}

func (nm *NetworkManager) createNetworkNeighbor(networkEvent networkmanager.NetworkEvent, namespace string) *v1beta1.NetworkNeighbor {
	var neighborEntry v1beta1.NetworkNeighbor

	portIdentifier := networkmanager.GeneratePortIdentifierFromEvent(networkEvent)
	neighborEntry.Ports = []v1beta1.NetworkPort{{
		Protocol: v1beta1.Protocol(networkEvent.Protocol),
		Port:     ptr.To(int32(networkEvent.Port)),
		Name:     portIdentifier,
	}}

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
		svc, err := nm.k8sClient.GetWorkload(networkEvent.Destination.Namespace, "Service", networkEvent.Destination.Name)
		if err != nil {
			logger.L().Warning("NetworkManager - failed to get service", helpers.String("reason", err.Error()), helpers.String("service name", networkEvent.Destination.Name))
			return nil
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
			// FIXME check if we need to handle services with no selectors
			return nil
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
			return nil
		}
		neighborEntry.IPAddress = networkEvent.Destination.IPAddress

		if nm.dnsResolverClient != nil {
			domain, ok := nm.dnsResolverClient.ResolveIPAddress(networkEvent.Destination.IPAddress)
			if ok {
				neighborEntry.DNS = domain
				neighborEntry.DNSNames = []string{domain}
			}
		}
	}

	neighborEntry.Type = networkmanager.InternalTrafficType
	if neighborEntry.NamespaceSelector == nil && neighborEntry.PodSelector == nil {
		neighborEntry.Type = networkmanager.ExternalTrafficType
	}

	identifier, err := utils.GenerateNeighborsIdentifier(neighborEntry)
	if err != nil {
		identifier = uuid.New().String()
	}
	neighborEntry.Identifier = identifier

	return &neighborEntry
}
