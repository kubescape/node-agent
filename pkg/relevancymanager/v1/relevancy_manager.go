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
	"sync"
	"time"

	"github.com/armosec/utils-k8s-go/wlid"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler"
	instanceidhandlerV1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type RelevancyManager struct {
	cfg                      config.Config
	clusterName              string
	ctx                      context.Context
	fileHandler              filehandler.FileHandler
	k8sClient                k8sclient.K8sClientInterface
	sbomHandler              sbomhandler.SBOMHandlerClient
	watchedContainerChannels sync.Map
}

var _ relevancymanager.RelevancyManagerClient = (*RelevancyManager)(nil)

func CreateRelevancyManager(ctx context.Context, cfg config.Config, clusterName string, fileHandler filehandler.FileHandler, k8sClient k8sclient.K8sClientInterface, sbomHandler sbomhandler.SBOMHandlerClient) (*RelevancyManager, error) {
	return &RelevancyManager{
		cfg:         cfg,
		clusterName: clusterName,
		ctx:         ctx,
		fileHandler: fileHandler,
		k8sClient:   k8sClient,
		sbomHandler: sbomHandler,
	}, nil
}

func (rm *RelevancyManager) deleteResources(watchedContainer *utils.WatchedContainerData) {
	watchedContainer.UpdateDataTicker.Stop()
	rm.sbomHandler.DecrementImageUse(watchedContainer.ImageID)
	rm.watchedContainerChannels.Delete(watchedContainer.ContainerID)

	// Remove container from the file DB
	_ = rm.fileHandler.RemoveBucket(watchedContainer.ContainerID)
}

func (rm *RelevancyManager) ensureImageInfo(container *containercollection.Container, watchedContainer *utils.WatchedContainerData) {
	if watchedContainer.ImageID == "" || watchedContainer.ImageTag == "" || watchedContainer.InstanceID == nil || watchedContainer.Wlid == "" {
		imageID, imageTag, parentWlid, instanceID, err := rm.getContainerInfo(container.K8s.Namespace, container.K8s.PodName, container.K8s.ContainerName)
		if err != nil {
			logger.L().Debug("failed to get image info", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", watchedContainer.K8sContainerID), helpers.Error(err))
			return
		}
		watchedContainer.ImageID = imageID
		watchedContainer.ImageTag = imageTag
		watchedContainer.InstanceID = instanceID
		watchedContainer.Wlid = parentWlid
		rm.sbomHandler.IncrementImageUse(watchedContainer.ImageID)
	}
}

func (rm *RelevancyManager) getContainerInfo(namespace, podName, containerName string) (string, string, string, instanceidhandler.IInstanceID, error) {
	imageID := ""
	imageTag := ""
	parentWlid := ""
	var instanceID instanceidhandler.IInstanceID
	wl, err := rm.k8sClient.GetWorkload(namespace, "Pod", podName)
	if err != nil {
		return imageID, imageTag, parentWlid, instanceID, fmt.Errorf("fail to get pod %s in namespace %s with error: %v", podName, namespace, err)
	}
	pod := wl.(*workloadinterface.Workload)
	// find parentWlid
	kind, name, err := rm.k8sClient.CalculateWorkloadParentRecursive(pod)
	if err != nil {
		return imageID, imageTag, parentWlid, instanceID, fmt.Errorf("fail to get workload owner parent %s in namespace %s with error: %v", pod.GetName(), pod.GetNamespace(), err)
	}
	parentWorkload, err := rm.k8sClient.GetWorkload(pod.GetNamespace(), kind, name)
	if err != nil {
		return imageID, imageTag, parentWlid, instanceID, fmt.Errorf("fail to get parent workload %s in namespace %s with error: %v", pod.GetName(), pod.GetNamespace(), err)
	}
	w := parentWorkload.(*workloadinterface.Workload)
	parentWlid = w.GenerateWlid(rm.clusterName)
	err = wlid.IsWlidValid(parentWlid)
	if err != nil {
		return imageID, imageTag, parentWlid, instanceID, fmt.Errorf("WLID of parent workload is not in the right %s in namespace %s with error: %v", pod.GetName(), pod.GetNamespace(), err)
	}
	// find imageTag
	containers, err := pod.GetContainers()
	if err != nil {
		return imageID, imageTag, parentWlid, instanceID, fmt.Errorf("fail to get containers for pod %s in namespace %s with error: %v", podName, namespace, err)
	}
	for i := range containers {
		if containers[i].Name == containerName {
			imageTag = containers[i].Image
		}
	}
	if imageTag == "" {
		return imageID, imageTag, parentWlid, instanceID, fmt.Errorf("fail to find container %s in pod %s in namespace %s", containerName, podName, namespace)
	}
	// find imageID
	status, err := pod.GetPodStatus() // Careful this is not available on container creation
	if err != nil {
		return imageID, imageTag, parentWlid, instanceID, fmt.Errorf("fail to get status for pod %s in namespace %s with error: %v", pod.GetName(), pod.GetNamespace(), err)
	}
	for i := range status.ContainerStatuses {
		if status.ContainerStatuses[i].Name == containerName {
			imageID = status.ContainerStatuses[i].ImageID
		}
	}
	if imageID == "" {
		return imageID, imageTag, parentWlid, instanceID, fmt.Errorf("fail to find container status %s in pod %s in namespace %s", containerName, podName, namespace)
	}
	// find instanceID
	instanceIDs, err := instanceidhandlerV1.GenerateInstanceID(pod)
	if err != nil {
		return imageID, imageTag, parentWlid, instanceID, fmt.Errorf("fail to create InstanceID to pod %s in namespace %s with error: %v", pod.GetName(), pod.GetNamespace(), err)
	}
	instanceID = instanceIDs[0]
	for i := range instanceIDs {
		if instanceIDs[i].GetContainerName() == containerName {
			instanceID = instanceIDs[i]
		}
	}
	return imageID, imageTag, parentWlid, instanceID, nil
}

// Handle relevant data
func (rm *RelevancyManager) handleRelevancy(ctx context.Context, watchedContainer *utils.WatchedContainerData, containerID string) {
	ctxPostSBOM, spanPostSBOM := otel.Tracer("").Start(ctx, "RelevancyManager.handleRelevancy")
	defer spanPostSBOM.End()

	// SBOM validation moved to monitorContainer

	fileList, err := rm.fileHandler.GetAndDeleteFiles(watchedContainer.K8sContainerID)
	if err != nil {
		logger.L().Debug("failed to get file list", helpers.String("container ID", containerID), helpers.String("k8s workload", watchedContainer.K8sContainerID), helpers.Error(err))
		return
	}
	logger.L().Debug("fileList generated", helpers.String("container ID", containerID), helpers.String("k8s workload", watchedContainer.K8sContainerID), helpers.String("file list", fmt.Sprintf("%v", fileList)))

	ctx, span := otel.Tracer("").Start(ctxPostSBOM, "SBOMClient.FilterSBOM")
	if err = rm.sbomHandler.FilterSBOM(watchedContainer, fileList); err != nil {
		_ = rm.fileHandler.AddFiles(watchedContainer.K8sContainerID, fileList)
		logger.L().Ctx(ctx).Warning("failed to filter SBOM", helpers.String("container ID", containerID), helpers.String("k8s workload", watchedContainer.K8sContainerID), helpers.Error(err))
		span.End()
		return
	}
	span.End()
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
			// ensure we know the imageID
			rm.ensureImageInfo(container, watchedContainer)
			// handle collection of relevant data
			rm.handleRelevancy(ctx, watchedContainer, container.Runtime.ContainerID)
		case err := <-watchedContainer.SyncChannel:
			switch {
			case errors.Is(err, utils.ContainerHasTerminatedError):
				// ensure we know the imageID
				rm.ensureImageInfo(container, watchedContainer)
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
		ContainerID:                              container.Runtime.ContainerID,
		UpdateDataTicker:                         time.NewTicker(rm.cfg.InitialDelay),
		SyncChannel:                              make(chan error, 10),
		K8sContainerID:                           k8sContainerID,
		RelevantRealtimeFilesByPackageSourceInfo: map[string]*utils.PackageSourceInfoData{},
		RelevantRealtimeFilesBySPDXIdentifier:    map[v1beta1.ElementID]bool{},
	}
	rm.watchedContainerChannels.Store(watchedContainer.ContainerID, watchedContainer.SyncChannel)

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
	ctx, span := otel.Tracer("").Start(rm.ctx, "RelevancyManager.ContainerCallback", trace.WithAttributes(attribute.String("containerID", notif.Container.Runtime.ContainerID), attribute.String("k8s workload", k8sContainerID)))
	defer span.End()

	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		_, exist := rm.watchedContainerChannels.Load(notif.Container.Runtime.ContainerID)
		if exist {
			logger.L().Debug("container already exist in memory", helpers.String("container ID", notif.Container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
			return
		}
		go rm.startRelevancyProcess(ctx, notif.Container, k8sContainerID)
	case containercollection.EventTypeRemoveContainer:
		if channel, ok := rm.watchedContainerChannels.LoadAndDelete(notif.Container.Runtime.ContainerID); ok {
			if !ok {
				logger.L().Debug("container not found in memory", helpers.String("container ID", notif.Container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
				return
			}
			channel.(chan error) <- utils.ContainerHasTerminatedError
		}
	}
}

func (rm *RelevancyManager) ReportFileAccess(k8sContainerID, file string) {
	rm.fileHandler.AddFile(k8sContainerID, file)
}
