package relevancymanager

import (
	"context"
	"errors"
	"fmt"
	"node-agent/pkg/config"
	"node-agent/pkg/containerwatcher"
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
	"github.com/panjf2000/ants/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	eventsWorkersConcurrency = 10
)

type RelevancyManager struct {
	cfg         config.Config
	clusterName string
	// FIXME we need this circular dependency to unregister the tracer at the end of startRelevancyProcess
	containerHandler         containerwatcher.ContainerWatcher
	fileHandler              filehandler.FileHandler
	k8sClient                k8sclient.K8sClientInterface
	sbomHandler              sbomhandler.SBOMHandlerClient
	watchedContainerChannels sync.Map
	eventWorkerPool          *ants.PoolWithFunc
}

var _ relevancymanager.RelevancyManagerClient = (*RelevancyManager)(nil)

func CreateRelevancyManager(cfg config.Config, clusterName string, fileHandler filehandler.FileHandler, k8sClient k8sclient.K8sClientInterface, sbomHandler sbomhandler.SBOMHandlerClient) (*RelevancyManager, error) {
	pool, err := ants.NewPoolWithFunc(eventsWorkersConcurrency, func(i interface{}) {
		s := i.([2]string)
		fileHandler.AddFile(s[0], s[1])
	})
	if err != nil {
		return nil, err
	}
	return &RelevancyManager{
		cfg:             cfg,
		clusterName:     clusterName,
		fileHandler:     fileHandler,
		k8sClient:       k8sClient,
		sbomHandler:     sbomHandler,
		eventWorkerPool: pool,
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
			logger.L().Debug("failed to get imageTag", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", watchedContainer.K8sContainerID), helpers.Error(err))
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
	now := time.Now()
	stopSniffingTime := now.Add(rm.cfg.MaxSniffingTime)
	for time.Now().Before(stopSniffingTime) {
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
			case errors.Is(err, relevancymanager.ContainerHasTerminatedError):
				// ensure we know the imageID
				rm.ensureImageInfo(container, watchedContainer)
				// handle collection of relevant data one more time
				rm.handleRelevancy(ctx, watchedContainer, container.Runtime.ContainerID)
				return relevancymanager.ContainerHasTerminatedError
			case errors.Is(err, relevancymanager.IncompleteSBOMError):
				return relevancymanager.IncompleteSBOMError
			}
		}
	}
	return nil
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
		logger.L().Info("stop monitor on container", helpers.String("reason", err.Error()), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
	} else {
		logger.L().Info("stop monitor on container - after monitoring time", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
	}

	rm.containerHandler.UnregisterContainer(container)
	err := rm.fileHandler.RemoveBucket(k8sContainerID)
	if err != nil {
		logger.L().Error("failed to remove container bucket", helpers.Error(err), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
	}
	rm.deleteResources(watchedContainer)
}

func (rm *RelevancyManager) ReportContainerStarted(ctx context.Context, container *containercollection.Container) {
	k8sContainerID := utils.CreateK8sContainerID(container.K8s.Namespace, container.K8s.PodName, container.K8s.ContainerName)
	ctx, span := otel.Tracer("").Start(ctx, "RelevancyManager.ReportContainerStarted", trace.WithAttributes(attribute.String("containerID", container.Runtime.ContainerID), attribute.String("k8s workload", k8sContainerID)))
	defer span.End()

	logger.L().Debug("handleContainerRunningEvent", helpers.Interface("container", container))
	_, exist := rm.watchedContainerChannels.Load(container.Runtime.ContainerID)
	if exist {
		logger.L().Debug("container already exist in memory", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
		return
	}
	logger.L().Info("new container has loaded - start monitor it", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
	go rm.startRelevancyProcess(ctx, container, k8sContainerID)
}

func (rm *RelevancyManager) ReportContainerTerminated(ctx context.Context, container *containercollection.Container) {
	k8sContainerID := utils.CreateK8sContainerID(container.K8s.Namespace, container.K8s.PodName, container.K8s.ContainerName)
	_, span := otel.Tracer("").Start(ctx, "RelevancyManager.ReportContainerTerminated", trace.WithAttributes(attribute.String("containerID", container.Runtime.ContainerID), attribute.String("k8s workload", k8sContainerID)))
	defer span.End()

	if channel, ok := rm.watchedContainerChannels.LoadAndDelete(container.Runtime.ContainerID); ok {
		if !ok {
			logger.L().Debug("container not found in memory", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
			return
		}
		channel.(chan error) <- relevancymanager.ContainerHasTerminatedError
	}
}

func (rm *RelevancyManager) ReportFileAccess(_ context.Context, namespace, pod, container, file string) {
	// log accessed files for all containers to avoid race condition
	// this won't record unnecessary containers as the containerCollection takes care of filtering them
	if file == "" {
		return
	}
	k8sContainerID := utils.CreateK8sContainerID(namespace, pod, container)
	_ = rm.eventWorkerPool.Invoke([2]string{k8sContainerID, file})
}

func (rm *RelevancyManager) SetContainerHandler(containerHandler containerwatcher.ContainerWatcher) {
	rm.containerHandler = containerHandler
}
