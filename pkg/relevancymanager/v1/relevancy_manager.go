package relevancymanager

import (
	"context"
	"errors"
	"fmt"
	"node-agent/pkg/config"
	"node-agent/pkg/filehandler"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/relevancymanager"
	"node-agent/pkg/sbomhandler"
	"node-agent/pkg/utils"
	"time"

	"github.com/cenkalti/backoff/v4"
	mapset "github.com/deckarep/golang-set/v2"

	"github.com/armosec/utils-k8s-go/wlid"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler"
	instanceidhandlerV1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	v1 "k8s.io/api/core/v1"
)

type RelevancyManager struct {
	cfg                      config.Config
	watchedContainerChannels maps.SafeMap[string, chan error]
	ctx                      context.Context
	fileHandler              filehandler.FileHandler
	k8sClient                k8sclient.K8sClientInterface
	sbomHandler              sbomhandler.SBOMHandlerClient
	preRunningContainerIDs   mapset.Set[string]
	removedContainers        mapset.Set[string]
	clusterName              string
}

var _ relevancymanager.RelevancyManagerClient = (*RelevancyManager)(nil)

func CreateRelevancyManager(ctx context.Context, cfg config.Config, clusterName string, fileHandler filehandler.FileHandler, k8sClient k8sclient.K8sClientInterface, sbomHandler sbomhandler.SBOMHandlerClient, preRunningContainerIDs mapset.Set[string]) (*RelevancyManager, error) {
	return &RelevancyManager{
		cfg:                    cfg,
		clusterName:            clusterName,
		ctx:                    ctx,
		fileHandler:            fileHandler,
		k8sClient:              k8sClient,
		sbomHandler:            sbomHandler,
		preRunningContainerIDs: preRunningContainerIDs,
		removedContainers:      mapset.NewSet[string](),
	}, nil
}

func (rm *RelevancyManager) deleteResources(watchedContainer *utils.WatchedContainerData) {
	watchedContainer.UpdateDataTicker.Stop()
	rm.sbomHandler.DecrementImageUse(watchedContainer.ImageID)
	rm.watchedContainerChannels.Delete(watchedContainer.ContainerID)
	rm.removedContainers.Add(watchedContainer.ContainerID)

	// Remove container from the file DB
	_ = rm.fileHandler.RemoveBucket(watchedContainer.ContainerID)
}

func (rm *RelevancyManager) ensureImageInfo(container *containercollection.Container, watchedContainer *utils.WatchedContainerData) error {

	if watchedContainer.ImageID == "" || watchedContainer.ImageTag == "" || watchedContainer.InstanceID == nil || watchedContainer.Wlid == "" {
		imageID, imageTag, parentWlid, parentResourceVersion, podTemplateHash, instanceID, err := rm.getContainerInfo(watchedContainer, container.K8s.Namespace, container.K8s.PodName, container.K8s.ContainerName)
		if err != nil {
			return fmt.Errorf("failed to get image info: %v", err)
		}
		watchedContainer.ImageID = imageID
		watchedContainer.ImageTag = imageTag
		watchedContainer.InstanceID = instanceID
		watchedContainer.Wlid = parentWlid
		watchedContainer.ParentResourceVersion = parentResourceVersion
		watchedContainer.TemplateHash = podTemplateHash
		rm.sbomHandler.IncrementImageUse(watchedContainer.ImageID)
	}
	return nil
}

func (rm *RelevancyManager) getContainerInfo(watchedContainer *utils.WatchedContainerData, namespace, podName, containerName string) (string, string, string, string, string, instanceidhandler.IInstanceID, error) {
	imageID := ""
	imageTag := ""
	parentWlid := ""
	parentResourceVersion := ""
	podTemplateHash := ""

	var instanceID instanceidhandler.IInstanceID
	wl, err := rm.k8sClient.GetWorkload(namespace, "Pod", podName)
	if err != nil {
		return imageID, imageTag, parentWlid, parentResourceVersion, podTemplateHash, instanceID, fmt.Errorf("fail to get pod %s in namespace %s with error: %v", podName, namespace, err)
	}
	pod := wl.(*workloadinterface.Workload)

	watchedContainer.SetContainerInfo(pod, containerName)

	// get pod template hash
	podTemplateHash, _ = pod.GetLabel("pod-template-hash")

	// find parentWlid
	kind, name, err := rm.k8sClient.CalculateWorkloadParentRecursive(pod)
	if err != nil {
		return imageID, imageTag, parentWlid, parentResourceVersion, podTemplateHash, instanceID, fmt.Errorf("fail to get workload owner parent %s in namespace %s with error: %v", pod.GetName(), pod.GetNamespace(), err)
	}
	parentWorkload, err := rm.k8sClient.GetWorkload(pod.GetNamespace(), kind, name)
	if err != nil {
		return imageID, imageTag, parentWlid, parentResourceVersion, podTemplateHash, instanceID, fmt.Errorf("fail to get parent workload %s in namespace %s with error: %v", pod.GetName(), pod.GetNamespace(), err)
	}
	w := parentWorkload.(*workloadinterface.Workload)
	parentWlid = w.GenerateWlid(rm.clusterName)
	parentResourceVersion = w.GetResourceVersion()
	err = wlid.IsWlidValid(parentWlid)
	if err != nil {
		return imageID, imageTag, parentWlid, parentResourceVersion, podTemplateHash, instanceID, fmt.Errorf("WLID of parent workload is not in the right %s in namespace %s with error: %v", pod.GetName(), pod.GetNamespace(), err)
	}

	imageTag, err = findImageTag(pod, containerName, watchedContainer.ContainerType)
	if err != nil {
		return imageID, imageTag, parentWlid, parentResourceVersion, podTemplateHash, instanceID, fmt.Errorf("fail to get containers for pod %s in namespace %s with error: %v", podName, namespace, err)
	}
	if imageTag == "" {
		return imageID, imageTag, parentWlid, parentResourceVersion, podTemplateHash, instanceID, fmt.Errorf("failed to find container %s in pod %s in namespace %s", containerName, podName, namespace)
	}

	// find imageID
	imageID, err = findImageID(pod, containerName, watchedContainer.ContainerType)
	if err != nil {
		return imageID, imageTag, parentWlid, parentResourceVersion, podTemplateHash, instanceID, fmt.Errorf("fail to get containers for pod %s in namespace %s with error: %v", podName, namespace, err)
	}
	if imageID == "" {
		return imageID, imageTag, parentWlid, parentResourceVersion, podTemplateHash, instanceID, fmt.Errorf("failed to find container status %s in pod %s in namespace %s", containerName, podName, namespace)
	}

	// find instanceID
	instanceIDs, err := instanceidhandlerV1.GenerateInstanceID(pod)
	if err != nil {
		return imageID, imageTag, parentWlid, parentResourceVersion, podTemplateHash, instanceID, fmt.Errorf("fail to create InstanceID to pod %s in namespace %s with error: %v", pod.GetName(), pod.GetNamespace(), err)
	}
	instanceID = instanceIDs[0]
	for i := range instanceIDs {
		if instanceIDs[i].GetInstanceType() != utils.ToInstanceType(watchedContainer.ContainerType) {
			continue
		}
		if instanceIDs[i].GetContainerName() == containerName {
			instanceID = instanceIDs[i]
		}
	}
	return imageID, imageTag, parentWlid, parentResourceVersion, podTemplateHash, instanceID, nil
}

// Handle relevant data
func (rm *RelevancyManager) handleRelevancy(ctx context.Context, watchedContainer *utils.WatchedContainerData, containerID string) {
	ctxPostSBOM, spanPostSBOM := otel.Tracer("").Start(ctx, "RelevancyManager.handleRelevancy")
	defer spanPostSBOM.End()

	if watchedContainer.InstanceID == nil {
		logger.L().Debug("ignoring container with empty instanceID", helpers.String("container ID", containerID), helpers.String("k8s workload", watchedContainer.K8sContainerID))
		return
	}
	fileList, err := rm.fileHandler.GetAndDeleteFiles(watchedContainer.K8sContainerID)
	if err != nil {
		logger.L().Debug("failed to get file list", helpers.String("container ID", containerID), helpers.String("k8s workload", watchedContainer.K8sContainerID), helpers.Error(err))
		return
	}

	ctx, span := otel.Tracer("").Start(ctxPostSBOM, "SBOMClient.FilterSBOM")
	if err = rm.sbomHandler.FilterSBOM(watchedContainer, fileList); err != nil {
		_ = rm.fileHandler.AddFiles(watchedContainer.K8sContainerID, fileList)
		logger.L().Ctx(ctx).Warning("failed to filter SBOM", helpers.String("container ID", containerID), helpers.String("k8s workload", watchedContainer.K8sContainerID), helpers.Error(err))
		span.End()
		return
	}
	span.End()
}

func findImageID(pod workloadinterface.IWorkload, containerName string, containerType utils.ContainerType) (string, error) {
	var containerStatuses []v1.ContainerStatus
	// find imageID
	podStatus, err := pod.GetPodStatus() // Careful this is not available on container creation
	if err != nil {
		return "", err
	}
	switch containerType {
	case utils.Container:
		containerStatuses = podStatus.ContainerStatuses
	case utils.InitContainer:
		containerStatuses = podStatus.InitContainerStatuses
	case utils.EphemeralContainer:
		containerStatuses = podStatus.EphemeralContainerStatuses
	}

	for i := range containerStatuses {
		if containerStatuses[i].Name == containerName {
			return containerStatuses[i].ImageID, nil
		}
	}
	return "", nil

}
func findImageTag(pod workloadinterface.IWorkload, containerName string, containerType utils.ContainerType) (string, error) {
	var containers []v1.Container
	var ephemeralContainers []v1.EphemeralContainer
	var err error

	switch containerType {
	case utils.Container:
		containers, err = pod.GetContainers()
		if err != nil {
			return "", err
		}
	case utils.InitContainer:
		containers, err = pod.GetInitContainers()
		if err != nil {
			return "", err
		}
	case utils.EphemeralContainer:
		ephemeralContainers, err = pod.GetEphemeralContainers()
		if err != nil {
			return "", err
		}

	}
	for i := range containers {
		if containers[i].Name == containerName {
			return containers[i].Image, nil
		}
	}
	for i := range ephemeralContainers {
		if ephemeralContainers[i].Name == containerName {
			return ephemeralContainers[i].Image, nil
		}
	}

	return "", nil

}
func (rm *RelevancyManager) monitorContainer(ctx context.Context, container *containercollection.Container, watchedContainer *utils.WatchedContainerData) error {
	for {
		select {
		case <-watchedContainer.UpdateDataTicker.C:
			// adjust ticker after first tick
			if !watchedContainer.InitialDelayExpired {
				watchedContainer.InitialDelayExpired = true
				watchedContainer.UpdateDataTicker.Reset(rm.cfg.UpdateDataPeriod)
			}
			// handle collection of relevant data
			rm.handleRelevancy(ctx, watchedContainer, container.Runtime.ContainerID)
		case err := <-watchedContainer.SyncChannel:
			switch {
			case errors.Is(err, utils.ContainerHasTerminatedError):
				// handle collection of relevant data one more time
				rm.handleRelevancy(ctx, watchedContainer, container.Runtime.ContainerID)
				return nil
			case errors.Is(err, utils.IncompleteSBOMError):
				return utils.IncompleteSBOMError
			}
		}
	}
}

func (rm *RelevancyManager) startRelevancyProcess(ctx context.Context, container *containercollection.Container, k8sContainerID string) {
	ctx, span := otel.Tracer("").Start(ctx, "RelevancyManager.startRelevancyProcess")
	defer span.End()

	watchedContainer := &utils.WatchedContainerData{
		ContainerID:      container.Runtime.ContainerID,
		UpdateDataTicker: time.NewTicker(rm.cfg.InitialDelay),
		SyncChannel:      make(chan error, 10),
		K8sContainerID:   k8sContainerID,
		RelevantRelationshipsArtifactsByIdentifier: make(map[string]bool),
		RelevantArtifactsFilesByIdentifier:         make(map[string]bool),
		RelevantRealtimeFilesByIdentifier:          make(map[string]bool),
	}

	// don't start monitoring until we have the image info - need to retry until the Pod is updated
	if err := backoff.Retry(func() error {
		return rm.ensureImageInfo(container, watchedContainer)
	}, backoff.NewExponentialBackOff()); err != nil {
		logger.L().Ctx(ctx).Error("RelevancyManager - failed to ensure image info", helpers.Error(err),
			helpers.String("container ID", watchedContainer.ContainerID),
			helpers.String("k8s workload", watchedContainer.K8sContainerID))
	}
	rm.removedContainers.Remove(watchedContainer.ContainerID)
	rm.watchedContainerChannels.Set(watchedContainer.ContainerID, watchedContainer.SyncChannel)
	if err := rm.monitorContainer(ctx, container, watchedContainer); err != nil {
		logger.L().Info("RelevancyManager - stop monitor on container", helpers.String("reason", err.Error()), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
	}

	err := rm.fileHandler.RemoveBucket(k8sContainerID)
	if err != nil {
		logger.L().Error("failed to remove container bucket", helpers.Error(err), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
	}
	rm.deleteResources(watchedContainer)
}

func (rm *RelevancyManager) ContainerCallback(notif containercollection.PubSubEvent) {
	k8sContainerID := utils.CreateK8sContainerID(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.ContainerName)
	// ignore pre-running containers
	if rm.preRunningContainerIDs.Contains(notif.Container.Runtime.ContainerID) {
		logger.L().Debug("ignoring pre-running container", helpers.String("container ID", notif.Container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
		return
	}

	ctx, span := otel.Tracer("").Start(rm.ctx, "RelevancyManager.ContainerCallback", trace.WithAttributes(attribute.String("containerID", notif.Container.Runtime.ContainerID), attribute.String("k8s workload", k8sContainerID)))
	defer span.End()

	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		if rm.watchedContainerChannels.Has(notif.Container.Runtime.ContainerID) {
			logger.L().Debug("container already exist in memory", helpers.String("container ID", notif.Container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
			return
		}
		go rm.startRelevancyProcess(ctx, notif.Container, k8sContainerID)

		// stop monitoring after MaxSniffingTime
		time.AfterFunc(rm.cfg.MaxSniffingTime, func() {
			event := containercollection.PubSubEvent{
				Timestamp: time.Now().Format(time.RFC3339),
				Type:      containercollection.EventTypeRemoveContainer,
				Container: notif.Container,
			}
			rm.ContainerCallback(event)
		})
	case containercollection.EventTypeRemoveContainer:
		channel := rm.watchedContainerChannels.Get(notif.Container.Runtime.ContainerID)
		if channel != nil {
			channel <- utils.ContainerHasTerminatedError
		}
		rm.watchedContainerChannels.Delete(notif.Container.Runtime.ContainerID)
		rm.removedContainers.Add(notif.Container.Runtime.ContainerID)
	}
}

func (rm *RelevancyManager) ReportFileExec(containerID, k8sContainerID, file string) {
	if rm.preRunningContainerIDs.Contains(containerID) {
		return
	}
	if rm.removedContainers.Contains(containerID) {
		return
	}

	rm.fileHandler.AddFile(k8sContainerID, file)
}

func (rm *RelevancyManager) ReportFileOpen(containerID, k8sContainerID, file string) {
	if rm.preRunningContainerIDs.Contains(containerID) {
		return
	}
	if rm.removedContainers.Contains(containerID) {
		return
	}
	rm.fileHandler.AddFile(k8sContainerID, file)
}
