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
	"node-agent/pkg/sbom"
	sbomV1 "node-agent/pkg/sbom/v1"
	"node-agent/pkg/storageclient"
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
	"github.com/panjf2000/ants/v2"
	"github.com/spf13/afero"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	eventsWorkersConcurrency = 10
	RelevantCVEsService      = "RelevantCVEsService"
	StepGetSBOM              = "StepGetSBOM"
	StepValidateSBOM         = "StepValidateSBOM"
	StepEventAggregator      = "StepEventAggregator"
)

var (
	containerHasTerminatedError = errors.New("container has terminated")
)

type RelevancyManager struct {
	afterTimerActionsChannel chan afterTimerActionsData
	cfg                      config.Config
	clusterName              string
	// FIXME we need this circular dependency to unregister the tracer at the end of startRelevancyProcess
	containerHandler  containerwatcher.ContainerWatcher
	fileHandler       filehandler.FileHandler
	k8sClient         k8sclient.K8sClientInterface
	sbomFs            afero.Fs
	storageClient     storageclient.StorageClient
	watchedContainers sync.Map
	eventWorkerPool   *ants.PoolWithFunc
}

var _ relevancymanager.RelevancyManagerClient = (*RelevancyManager)(nil)

func CreateRelevancyManager(cfg config.Config, clusterName string, fileHandler filehandler.FileHandler, k8sClient k8sclient.K8sClientInterface, sbomFs afero.Fs, storageClient storageclient.StorageClient) (*RelevancyManager, error) {
	pool, err := ants.NewPoolWithFunc(eventsWorkersConcurrency, func(i interface{}) {
		s := i.([2]string)
		fileHandler.AddFile(s[0], s[1])
	})
	if err != nil {
		return nil, err
	}
	return &RelevancyManager{
		afterTimerActionsChannel: make(chan afterTimerActionsData, 50),
		cfg:                      cfg,
		clusterName:              clusterName,
		fileHandler:              fileHandler,
		k8sClient:                k8sClient,
		sbomFs:                   sbomFs,
		storageClient:            storageClient,
		watchedContainers:        sync.Map{},
		eventWorkerPool:          pool,
	}, nil
}

// Handle relevant data
func (rm *RelevancyManager) handleRelevancy(ctx context.Context, containerData watchedContainerData, containerID string) {

	ctxPostSBOM, spanPostSBOM := otel.Tracer("").Start(ctx, "PostFilterSBOM")
	defer spanPostSBOM.End()

	if err := containerData.sbomClient.ValidateSBOM(ctx); err != nil {
		logger.L().Info("SBOM is incomplete", helpers.String("container ID", containerID), helpers.String("k8s workload", containerData.k8sContainerID), helpers.Error(err))
		containerData.syncChannel[StepValidateSBOM] <- err
	}

	fileList, err := rm.fileHandler.GetFiles(containerData.k8sContainerID)
	if err != nil {
		logger.L().Debug("failed to get file list", helpers.String("container ID", containerID), helpers.String("k8s workload", containerData.k8sContainerID), helpers.Error(err))
		return
	}
	logger.L().Debug("fileList generated", helpers.String("container ID", containerID), helpers.String("k8s workload", containerData.k8sContainerID), helpers.String("file list", fmt.Sprintf("%v", fileList)))

	if err = containerData.sbomClient.FilterSBOM(fileList); err != nil {
		_ = rm.fileHandler.AddFiles(containerData.k8sContainerID, fileList)
		ctx, span := otel.Tracer("").Start(ctxPostSBOM, "FilterSBOM")
		defer span.End()
		logger.L().Ctx(ctx).Warning("failed to filter SBOM", helpers.String("container ID", containerID), helpers.String("k8s workload", containerData.k8sContainerID), helpers.Error(err))
		return
	}
	filterSBOMKey, err := containerData.instanceID.GetSlug()
	if err != nil {
		_ = rm.fileHandler.AddFiles(containerData.k8sContainerID, fileList)
		ctx, span := otel.Tracer("").Start(ctxPostSBOM, "filterSBOMKey")
		defer span.End()
		logger.L().Ctx(ctx).Warning("failed to get filterSBOMKey for store filter SBOM", helpers.String("container ID", containerID), helpers.String("k8s workload", containerData.k8sContainerID), helpers.Error(err))
		return
	}
	// it is safe to use containerData.imageID directly since we needed it to retrieve the SBOM
	if err = containerData.sbomClient.StoreFilterSBOM(containerData.imageID, filterSBOMKey); err != nil {
		if !errors.Is(err, sbom.IsAlreadyExist()) {
			_ = rm.fileHandler.AddFiles(containerData.k8sContainerID, fileList)
			ctx, span := otel.Tracer("").Start(ctxPostSBOM, "StoreFilterSBOM")
			defer span.End()
			logger.L().Ctx(ctx).Error("failed to store filtered SBOM", helpers.String("container ID", containerID), helpers.String("k8s workload", containerData.k8sContainerID), helpers.Error(err))
		}
		return
	}

	logger.L().Info("filtered SBOM has been stored successfully", helpers.String("containerID", containerID), helpers.String("k8s workload", containerData.k8sContainerID))
}
func (rm *RelevancyManager) afterTimerActions(ctx context.Context) error {
	for {
		afterTimerActionsData := <-rm.afterTimerActionsChannel
		containerDataInterface, exist := rm.watchedContainers.Load(afterTimerActionsData.containerID)
		if !exist {
			logger.L().Warning("afterTimerActions: failed to get container data", helpers.String("container ID", afterTimerActionsData.containerID))
			continue
		}
		containerData := containerDataInterface.(watchedContainerData)

		if rm.cfg.EnableRelevancy && afterTimerActionsData.service == RelevantCVEsService {

			if err := <-containerData.syncChannel[StepGetSBOM]; err != nil {
				logger.L().Debug("failed to get SBOM", helpers.String("container ID", afterTimerActionsData.containerID), helpers.String("k8s workload", containerData.k8sContainerID), helpers.Error(err))
				continue
			}
			if containerData.sbomClient == nil {
				// it is possible that the sbom client was not created yet
				logger.L().Debug("sbom client not yet created", helpers.String("container ID", afterTimerActionsData.containerID), helpers.String("k8s workload", containerData.k8sContainerID))
				continue
			}

			// handle collection of relevant data
			rm.handleRelevancy(ctx, containerData, afterTimerActionsData.containerID)
		}
	}
}

func (rm *RelevancyManager) deleteResources(watchedContainer watchedContainerData, containerID string) {
	watchedContainer.updateDataTicker.Stop()
	if watchedContainer.sbomClient != nil {
		watchedContainer.sbomClient.CleanResources()
	}
	rm.watchedContainers.Delete(containerID)

	// Remove container from the file DB
	_ = rm.fileHandler.RemoveBucket(watchedContainer.k8sContainerID)
}

func (rm *RelevancyManager) getSBOM(ctx context.Context, container *containercollection.Container) {
	ctx, span := otel.Tracer("").Start(ctx, "RelevancyManager.getSBOM")
	defer span.End()
	// get watchedContainer from map
	containerDataInterface, exist := rm.watchedContainers.Load(container.Runtime.ContainerID)
	if !exist {
		return
	}
	watchedContainer := containerDataInterface.(watchedContainerData)
	// skip if the SBOM is already retrieved
	if watchedContainer.sbomClient != nil && watchedContainer.sbomClient.IsSBOMAlreadyExist() {
		watchedContainer.syncChannel[StepGetSBOM] <- nil
		return
	}
	// FIXME: this is a workaround to let the pod be updated with container information, avoiding another try
	utils.RandomSleep(2, 10)
	// get watchedContainer from map
	containerDataInterface, exist = rm.watchedContainers.Load(container.Runtime.ContainerID)
	if !exist {
		return
	}
	watchedContainer = containerDataInterface.(watchedContainerData)
	// skip if the SBOM is already retrieved
	if watchedContainer.sbomClient != nil && watchedContainer.sbomClient.IsSBOMAlreadyExist() {
		watchedContainer.syncChannel[StepGetSBOM] <- nil
		return
	}
	// end of FIXME
	// get pod information, we cannot do this during ReportContainerStarted because the pod might not be updated yet with container information
	wl, err := rm.k8sClient.GetWorkload(container.K8s.Namespace, "Pod", container.K8s.PodName)
	if err != nil {
		logger.L().Ctx(ctx).Error("failed to get pod", helpers.Error(err), helpers.String("namespace", container.K8s.Namespace), helpers.String("Pod name", container.K8s.PodName))
		watchedContainer.syncChannel[StepGetSBOM] <- err
		return
	}
	workload := wl.(*workloadinterface.Workload)
	imageID, imageTag, parentWlid, instanceID, err := rm.parsePodData(workload, container)
	// This behavior will happen when the running container is an initContainer
	if err != nil || imageID == "" || imageTag == "" || parentWlid == "" || instanceID == nil {
		watchedContainer.syncChannel[StepGetSBOM] <- err
		return
	}
	// create sbomClient
	sbomClient := sbom.CreateSBOMStorageClient(rm.storageClient, parentWlid, instanceID, rm.sbomFs)

	// get SBOM
	err = sbomClient.GetSBOM(ctx, imageTag, imageID)

	// save watchedContainer with new fields
	watchedContainer.imageID = imageID
	watchedContainer.instanceID = instanceID
	watchedContainer.sbomClient = sbomClient
	rm.watchedContainers.Store(container.Runtime.ContainerID, watchedContainer)

	// notify the channel. This call must be at the end of the function as it will unblock the waitForTicks function
	watchedContainer.syncChannel[StepGetSBOM] <- err
}

func (rm *RelevancyManager) parsePodData(pod *workloadinterface.Workload, container *containercollection.Container) (string, string, string, instanceidhandler.IInstanceID, error) {

	kind, name, err := rm.k8sClient.CalculateWorkloadParentRecursive(pod)
	if err != nil {
		return "", "", "", nil, fmt.Errorf("fail to get workload owner parent %s in namespace %s with error: %v", pod.GetName(), pod.GetNamespace(), err)
	}
	parentWorkload, err := rm.k8sClient.GetWorkload(pod.GetNamespace(), kind, name)
	if err != nil {
		return "", "", "", nil, fmt.Errorf("fail to get parent workload %s in namespace %s with error: %v", pod.GetName(), pod.GetNamespace(), err)
	}
	w := parentWorkload.(*workloadinterface.Workload)
	parentWlid := w.GenerateWlid(rm.clusterName)
	err = wlid.IsWlidValid(parentWlid)
	if err != nil {
		return "", "", "", nil, fmt.Errorf("WLID of parent workload is not in the right %s in namespace %s with error: %v", pod.GetName(), pod.GetNamespace(), err)
	}

	containers, err := pod.GetContainers()
	if err != nil {
		return "", "", "", nil, fmt.Errorf("fail to get containers for pod %s in namespace %s with error: %v", pod.GetName(), pod.GetNamespace(), err)
	}
	imageTag := ""
	for i := range containers {
		if containers[i].Name == container.K8s.ContainerName {
			imageTag = containers[i].Image
		}
	}

	status, err := pod.GetPodStatus() // Careful this is not available on container creation
	if err != nil {
		return "", "", "", nil, fmt.Errorf("fail to get status for pod %s in namespace %s with error: %v", pod.GetName(), pod.GetNamespace(), err)
	}
	imageID := ""
	for i := range status.ContainerStatuses {
		if status.ContainerStatuses[i].Name == container.K8s.ContainerName {
			imageID = status.ContainerStatuses[i].ImageID
		}
	}

	instanceIDs, err := instanceidhandlerV1.GenerateInstanceID(pod)
	if err != nil {
		return "", "", "", nil, fmt.Errorf("fail to create InstanceID to pod %s in namespace %s with error: %v", pod.GetName(), pod.GetNamespace(), err)
	}
	instanceID := instanceIDs[0]
	for i := range instanceIDs {
		if instanceIDs[i].GetContainerName() == container.K8s.ContainerName {
			instanceID = instanceIDs[i]
		}
	}

	logger.L().Debug("parsePodData", helpers.String("imageID", imageID), helpers.String("imageTag", imageTag), helpers.String("parentWlid", parentWlid), helpers.String("instanceID", instanceID.GetStringFormatted()))
	return imageID, imageTag, parentWlid, instanceID, nil
}

func (rm *RelevancyManager) startRelevancyProcess(ctx context.Context, container *containercollection.Container, k8sContainerID string) {
	ctx, span := otel.Tracer("").Start(ctx, "RelevancyManager.startRelevancyProcess")
	defer span.End()

	watchedContainer := watchedContainerData{
		updateDataTicker: time.NewTicker(rm.cfg.InitialDelay),
		container:        container,
		syncChannel: map[string]chan error{
			StepGetSBOM:         make(chan error, 10),
			StepEventAggregator: make(chan error, 10),
			StepValidateSBOM:    make(chan error, 10),
		},
		k8sContainerID: k8sContainerID,
	}
	rm.watchedContainers.Store(container.Runtime.ContainerID, watchedContainer)

	if err := rm.monitorContainer(ctx, container, watchedContainer); err != nil {
		logger.L().Info("stop monitor on container", helpers.String("reason", err.Error()), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
	} else {
		logger.L().Info("stop monitor on container - after monitoring time", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
	}

	rm.containerHandler.UnregisterContainer(container)
	rm.deleteResources(watchedContainer, container.Runtime.ContainerID)
}

func (rm *RelevancyManager) monitorContainer(ctx context.Context, container *containercollection.Container, watchedContainer watchedContainerData) error {
	now := time.Now()
	stopSniffingTime := now.Add(rm.cfg.MaxSniffingTime)
	for time.Now().Before(stopSniffingTime) {
		rm.getSBOM(ctx, container)
		err := rm.waitForTicks(watchedContainer, container.Runtime.ContainerID)
		if err != nil {
			if errors.Is(err, containerHasTerminatedError) {
				return fmt.Errorf("container terminated")
			} else if errors.Is(err, sbomV1.SBOMIncomplete) {
				return fmt.Errorf("incomplete SBOM")
			}
		}
	}
	return nil
}

func (rm *RelevancyManager) waitForTicks(watchedContainer watchedContainerData, containerID string) error {
	var err error
	select {
	case <-watchedContainer.updateDataTicker.C:
		if rm.cfg.EnableRelevancy {
			rm.afterTimerActionsChannel <- afterTimerActionsData{
				containerID: containerID,
				service:     RelevantCVEsService,
			}
		}
		if !watchedContainer.initialDelayExpired {
			watchedContainer.initialDelayExpired = true
			watchedContainer.updateDataTicker.Reset(rm.cfg.UpdateDataPeriod)
		}
	case err = <-watchedContainer.syncChannel[StepEventAggregator]:
		if errors.Is(err, containerHasTerminatedError) {
			watchedContainer.updateDataTicker.Stop()
			err = containerHasTerminatedError
		}
	case err = <-watchedContainer.syncChannel[StepValidateSBOM]:
		if errors.Is(err, sbomV1.SBOMIncomplete) {
			return err
		}
	}
	return err
}

func (rm *RelevancyManager) ReportContainerStarted(ctx context.Context, container *containercollection.Container) {
	k8sContainerID := utils.CreateK8sContainerID(container.K8s.Namespace, container.K8s.PodName, container.K8s.ContainerName)
	ctx, span := otel.Tracer("").Start(ctx, "RelevancyManager.ReportContainerStarted", trace.WithAttributes(attribute.String("containerID", container.Runtime.ContainerID), attribute.String("k8s workload", k8sContainerID)))
	defer span.End()

	logger.L().Debug("handleContainerRunningEvent", helpers.Interface("container", container))
	_, exist := rm.watchedContainers.Load(container.Runtime.ContainerID)
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

	if watchedContainer, ok := rm.watchedContainers.LoadAndDelete(container.Runtime.ContainerID); ok {
		data, ok := watchedContainer.(watchedContainerData)
		if !ok {
			logger.L().Debug("container not found in memory", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
			return
		}
		err := rm.fileHandler.RemoveBucket(k8sContainerID)
		if err != nil {
			logger.L().Error("failed to remove container bucket", helpers.Error(err), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
			return
		}
		data.syncChannel[StepEventAggregator] <- containerHasTerminatedError
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

func (rm *RelevancyManager) StartRelevancyManager(ctx context.Context) {
	ctx, span := otel.Tracer("").Start(ctx, "RelevancyManager.StartRelevancyManager")
	defer span.End()
	go func() {
		_ = rm.afterTimerActions(ctx)
	}()
}
