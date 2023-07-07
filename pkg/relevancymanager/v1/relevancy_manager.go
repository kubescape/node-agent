package relevancymanager

import (
	"context"
	"errors"
	"fmt"
	"node-agent/pkg/config"
	"node-agent/pkg/containerwatcher"
	"node-agent/pkg/filehandler"
	"node-agent/pkg/relevancymanager"
	"node-agent/pkg/sbom"
	sbomV1 "node-agent/pkg/sbom/v1"
	"node-agent/pkg/storageclient"
	"node-agent/pkg/utils"
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	RelevantCVEsService = "RelevantCVEsService"
	StepGetSBOM         = "StepGetSBOM"
	StepValidateSBOM    = "StepValidateSBOM"
	StepEventAggregator = "StepEventAggregator"
)

var (
	containerHasTerminatedError = errors.New("container has terminated")
)

type RelevancyManager struct {
	afterTimerActionsChannel chan afterTimerActionsData
	cfg                      config.Config
	// FIXME we need this circular dependency to unregister the tracer at the end of startRelevancyProcess
	containerHandler  containerwatcher.ContainerWatcher
	fileHandler       filehandler.FileHandler
	storageClient     storageclient.StorageClient
	watchedContainers sync.Map
}

var _ relevancymanager.RelevancyManagerClient = (*RelevancyManager)(nil)

func CreateRelevancyManager(cfg config.Config, fileHandler filehandler.FileHandler, storageClient storageclient.StorageClient) (*RelevancyManager, error) {
	return &RelevancyManager{
		afterTimerActionsChannel: make(chan afterTimerActionsData, 50),
		cfg:                      cfg,
		fileHandler:              fileHandler,
		storageClient:            storageClient,
		watchedContainers:        sync.Map{},
	}, nil
}

func (rm *RelevancyManager) afterTimerActions(ctx context.Context) error {
	for {
		afterTimerActionsData := <-rm.afterTimerActionsChannel
		containerDataInterface, exist := rm.watchedContainers.Load(afterTimerActionsData.containerID)
		if !exist {
			logger.L().Ctx(ctx).Warning("afterTimerActions: failed to get container data", []helpers.IDetails{helpers.String("container ID", afterTimerActionsData.containerID)}...)
			continue
		}
		containerData := containerDataInterface.(watchedContainerData)

		if rm.cfg.EnableRelevancy && afterTimerActionsData.service == RelevantCVEsService {
			fileList, err := rm.fileHandler.GetFiles(ctx, containerData.k8sContainerID)
			if err != nil {
				logger.L().Debug("failed to get file list", []helpers.IDetails{helpers.String("container ID", afterTimerActionsData.containerID), helpers.String("container name", containerData.event.GetContainerName()), helpers.String("k8s resource ", containerData.event.GetK8SWorkloadID()), helpers.Error(err)}...)
				continue
			}
			logger.L().Debug("fileList generated", []helpers.IDetails{helpers.String("container ID", afterTimerActionsData.containerID), helpers.String("container name", containerData.event.GetContainerName()), helpers.String("k8s resource ", containerData.event.GetK8SWorkloadID()), helpers.String("file list", fmt.Sprintf("%v", fileList))}...)
			ctxPostSBOM, spanPostSBOM := otel.Tracer("").Start(ctx, "PostFilterSBOM")
			if err = <-containerData.syncChannel[StepGetSBOM]; err != nil {
				logger.L().Debug("failed to get SBOM", []helpers.IDetails{helpers.String("container ID", afterTimerActionsData.containerID), helpers.String("container name", containerData.event.GetContainerName()), helpers.String("k8s resource ", containerData.event.GetK8SWorkloadID()), helpers.Error(err)}...)
				continue
			}
			if err = containerData.sbomClient.ValidateSBOM(ctx); err != nil {
				ctx, span := otel.Tracer("").Start(ctxPostSBOM, "ValidateSBOM")
				logger.L().Ctx(ctx).Warning("SBOM is incomplete", []helpers.IDetails{helpers.String("container ID", afterTimerActionsData.containerID), helpers.String("container name", containerData.event.GetContainerName()), helpers.String("k8s resource ", containerData.event.GetK8SWorkloadID()), helpers.Error(err)}...)
				containerData.syncChannel[StepValidateSBOM] <- err
				span.End()
			}
			if err = containerData.sbomClient.FilterSBOM(ctx, fileList); err != nil {
				ctx, span := otel.Tracer("").Start(ctxPostSBOM, "FilterSBOM")
				logger.L().Ctx(ctx).Warning("failed to filter SBOM", []helpers.IDetails{helpers.String("container ID", afterTimerActionsData.containerID), helpers.String("container name", containerData.event.GetContainerName()), helpers.String("k8s resource", containerData.event.GetK8SWorkloadID()), helpers.Error(err)}...)
				span.End()
				continue
			}
			filterSBOMKey, err := containerData.event.GetInstanceID().GetSlug()
			if err != nil {
				ctx, span := otel.Tracer("").Start(ctxPostSBOM, "filterSBOMKey")
				logger.L().Ctx(ctx).Warning("failed to get filterSBOMKey for store filter SBOM", []helpers.IDetails{helpers.String("container ID", afterTimerActionsData.containerID), helpers.String("container name", containerData.event.GetContainerName()), helpers.String("k8s resource", containerData.event.GetK8SWorkloadID()), helpers.Error(err)}...)
				span.End()
				continue
			}
			// it is safe to use containerData.imageID directly since we needed it to retrieve the SBOM
			if err = containerData.sbomClient.StoreFilterSBOM(ctx, containerData.imageID, filterSBOMKey); err != nil {
				if !errors.Is(err, sbom.IsAlreadyExist()) {
					ctx, span := otel.Tracer("").Start(ctxPostSBOM, "StoreFilterSBOM")
					logger.L().Ctx(ctx).Error("failed to store filtered SBOM", []helpers.IDetails{helpers.String("container ID", afterTimerActionsData.containerID), helpers.String("k8s resource", containerData.event.GetK8SWorkloadID()), helpers.Error(err)}...)
					span.End()
				}
				continue
			}
			logger.L().Info("filtered SBOM has been stored successfully", []helpers.IDetails{helpers.String("containerID", afterTimerActionsData.containerID), helpers.String("k8s resource", containerData.event.GetK8SWorkloadID())}...)
			spanPostSBOM.End()
		}
	}
}

func (rm *RelevancyManager) deleteResources(watchedContainer watchedContainerData, containerID string) {
	watchedContainer.snifferTicker.Stop()
	watchedContainer.sbomClient.CleanResources()
	rm.watchedContainers.Delete(containerID)
}

func (rm *RelevancyManager) getSBOM(ctx context.Context, contEvent containerwatcher.ContainerEvent) {
	ctx, span := otel.Tracer("").Start(ctx, "RelevancyManager.getSBOM")
	defer span.End()

	containerDataInterface, exist := rm.watchedContainers.Load(contEvent.GetContainerID())
	if !exist {
		logger.L().Ctx(ctx).Error("getSBOM: failed to get container data of ContainerID, not exist in memory", helpers.String("containerID", contEvent.GetContainerID()))
		return
	}
	watchedContainer := containerDataInterface.(watchedContainerData)
	// save watchedContainer with imageID
	rm.watchedContainers.Store(contEvent.GetContainerID(), watchedContainer)
	err := watchedContainer.sbomClient.GetSBOM(ctx, contEvent.GetImageTAG(), contEvent.GetImageID())

	watchedContainer.syncChannel[StepGetSBOM] <- err
}

func (rm *RelevancyManager) startRelevancyProcess(ctx context.Context, contEvent containerwatcher.ContainerEvent) {
	ctx, span := otel.Tracer("").Start(ctx, "RelevancyManager.startRelevancyProcess")
	defer span.End()

	containerDataInterface, exist := rm.watchedContainers.Load(contEvent.GetContainerID())
	if !exist {
		ctx, span := otel.Tracer("").Start(ctx, "container monitoring", trace.WithAttributes(attribute.String("containerID", contEvent.GetContainerID()), attribute.String("container workload", contEvent.GetK8SWorkloadID())))
		defer span.End()
		logger.L().Ctx(ctx).Error("startRelevancyProcess: failed to get container data", helpers.String("container ID", contEvent.GetContainerID()), helpers.String("container name", contEvent.GetContainerName()), helpers.String("k8s resources", contEvent.GetK8SWorkloadID()))
		return
	}
	watchedContainer := containerDataInterface.(watchedContainerData)

	now := time.Now()
	stopSniffingTime := now.Add(rm.cfg.MaxSniffingTime)
	for time.Now().Before(stopSniffingTime) {
		go rm.getSBOM(ctx, contEvent)
		ctx, span := otel.Tracer("").Start(ctx, "container monitoring")
		err := rm.startTimer(watchedContainer, contEvent.GetContainerID())
		if err != nil {
			if errors.Is(err, containerHasTerminatedError) {
				break
			} else if errors.Is(err, sbomV1.SBOMIncomplete) {
				logger.L().Ctx(ctx).Warning("container monitoring stopped - incomplete SBOM", helpers.String("container ID", contEvent.GetContainerID()), helpers.String("container name", contEvent.GetContainerName()), helpers.String("k8s resources", contEvent.GetK8SWorkloadID()), helpers.Error(err))
				break
			}
		}
		span.End()
	}
	logger.L().Info("stop monitor on container - after monitoring time", helpers.String("container ID", contEvent.GetContainerID()), helpers.String("container name", contEvent.GetContainerName()), helpers.String("k8s resources", contEvent.GetK8SWorkloadID()))
	rm.containerHandler.UnregisterContainer(ctx, contEvent)
	rm.deleteResources(watchedContainer, contEvent.GetContainerID())
}

func (rm *RelevancyManager) startTimer(watchedContainer watchedContainerData, containerID string) error {
	var err error
	select {
	case <-watchedContainer.snifferTicker.C:
		if rm.cfg.EnableRelevancy {
			rm.afterTimerActionsChannel <- afterTimerActionsData{
				containerID: containerID,
				service:     RelevantCVEsService,
			}
		}
	case err = <-watchedContainer.syncChannel[StepEventAggregator]:
		if errors.Is(err, containerHasTerminatedError) {
			watchedContainer.snifferTicker.Stop()
			err = containerHasTerminatedError
		}
	case err = <-watchedContainer.syncChannel[StepValidateSBOM]:
		if errors.Is(err, sbomV1.SBOMIncomplete) {
			return err
		}
	}
	return err
}

func (rm *RelevancyManager) ReportContainerStarted(ctx context.Context, contEvent containerwatcher.ContainerEvent) {
	ctx, span := otel.Tracer("").Start(ctx, "RelevancyManager.ReportContainerStarted", trace.WithAttributes(attribute.String("containerID", contEvent.GetContainerID()), attribute.String("container workload", contEvent.GetK8SWorkloadID())))
	defer span.End()

	logger.L().Debug("handleContainerRunningEvent", helpers.Interface("contEvent", contEvent))
	_, exist := rm.watchedContainers.Load(contEvent.GetContainerID())
	if exist {
		logger.L().Debug("container already exist in memory", helpers.String("container ID", contEvent.GetContainerID()), helpers.String("container name", contEvent.GetContainerName()), helpers.String("k8s workload", contEvent.GetK8SWorkloadID()))
		return
	}
	logger.L().Info("new container has loaded - start monitor it", helpers.String("container ID", contEvent.GetContainerID()), helpers.String("container name", contEvent.GetContainerName()), helpers.String("k8s workload", contEvent.GetK8SWorkloadID()))
	newWatchedContainer := watchedContainerData{
		snifferTicker: time.NewTicker(rm.cfg.UpdateDataPeriod),
		event:         contEvent,
		sbomClient:    sbom.CreateSBOMStorageClient(rm.storageClient, contEvent.GetK8SWorkloadID(), contEvent.GetInstanceID()),
		syncChannel: map[string]chan error{
			StepGetSBOM:         make(chan error, 10),
			StepEventAggregator: make(chan error, 10),
			StepValidateSBOM:    make(chan error, 10),
		},
		k8sContainerID: contEvent.GetK8SContainerID(),
	}
	rm.watchedContainers.Store(contEvent.GetContainerID(), newWatchedContainer)
	go rm.startRelevancyProcess(ctx, contEvent)
}

func (rm *RelevancyManager) ReportContainerTerminated(ctx context.Context, contEvent containerwatcher.ContainerEvent) {
	ctx, span := otel.Tracer("").Start(ctx, "RelevancyManager.ReportContainerTerminated", trace.WithAttributes(attribute.String("containerID", contEvent.GetContainerID()), attribute.String("container workload", contEvent.GetK8SWorkloadID())))
	defer span.End()

	k8sContainerID := contEvent.GetK8SContainerID()
	if watchedContainer, ok := rm.watchedContainers.LoadAndDelete(contEvent.GetContainerID()); ok {
		data, ok := watchedContainer.(watchedContainerData)
		if !ok {
			logger.L().Debug("container not found in memory", helpers.String("container ID", contEvent.GetContainerID()), helpers.String("container name", contEvent.GetContainerName()), helpers.String("k8s workload", contEvent.GetK8SWorkloadID()))
			return
		}
		err := rm.fileHandler.RemoveBucket(ctx, k8sContainerID)
		if err != nil {
			logger.L().Ctx(ctx).Error("failed to remove container bucket", helpers.Error(err), helpers.String("container ID", contEvent.GetContainerID()), helpers.String("container name", contEvent.GetContainerName()), helpers.String("k8s workload", contEvent.GetK8SWorkloadID()))
			return
		}
		data.syncChannel[StepEventAggregator] <- containerHasTerminatedError
	}
}

func (rm *RelevancyManager) ReportFileAccess(ctx context.Context, namespace, pod, container, file string) {
	ctx, span := otel.Tracer("").Start(ctx, "RelevancyManager.ReportFileAccess")
	defer span.End()
	// log accessed files for all containers to avoid race condition
	// this won't record unnecessary containers as the containerCollection takes care of filtering them
	if file == "" {
		return
	}
	k8sContainerID := utils.CreateK8sContainerID(namespace, pod, container)
	err := rm.fileHandler.AddFile(ctx, k8sContainerID, file)
	if err != nil {
		logger.L().Ctx(ctx).Error("failed to add file to container file list", helpers.Error(err), helpers.Interface("k8sContainerID", k8sContainerID), helpers.String("file", file))
	}
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
