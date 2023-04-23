package conthandler

import (
	gcontext "context"
	"errors"
	"fmt"
	"sniffer/pkg/config"
	"sniffer/pkg/context"
	v1 "sniffer/pkg/conthandler/v1"
	accumulator "sniffer/pkg/event_data_storage"
	"sniffer/pkg/sbom"
	"sniffer/pkg/storageclient"
	"strings"
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
	StepEventAggregator = "StepEventAggregator"
)

var (
	containerAlreadyExistError  = errors.New("container already exist")
	containerHasTerminatedError = errors.New("container has terminated")
)

type supportedServices string

type afterTimerActionsData struct {
	containerID string
	service     supportedServices
}

type watchedContainerData struct {
	containerAggregator *Aggregator
	snifferTicker       *time.Ticker
	event               v1.ContainerEventData
	syncChannel         map[string]chan error
	sbomClient          sbom.SBOMClient
	ctx                 gcontext.Context
	span                trace.Span
}

type ContainerHandler struct {
	containerWatcher    *ContainerWatcher
	containersEventChan chan v1.ContainerEventData
	// watchedContainers        map[string]watchedContainerData
	// syncWatchedContainersMap *sync.RWMutex
	watchedContainers        sync.Map
	afterTimerActionsChannel chan afterTimerActionsData
	storageClient            storageclient.StorageClient
}

func CreateContainerHandler(contClient ContainerClient, storageClient storageclient.StorageClient) (*ContainerHandler, error) {

	contWatcher, err := CreateContainerWatcher(contClient)
	if err != nil {
		return nil, err
	}

	return &ContainerHandler{
		containersEventChan:      make(chan v1.ContainerEventData, 50),
		containerWatcher:         contWatcher,
		watchedContainers:        sync.Map{},
		afterTimerActionsChannel: make(chan afterTimerActionsData, 50),
		storageClient:            storageClient,
	}, nil
}

func (ch *ContainerHandler) afterTimerActions() error {
	var err error

	for {
		afterTimerActionsData := <-ch.afterTimerActionsChannel
		containerDataInterface, exist := ch.watchedContainers.Load(afterTimerActionsData.containerID)
		if !exist {
			logger.L().Ctx(context.GetBackgroundContext()).Warning("afterTimerActions: failed to get container data of container ID", []helpers.IDetails{helpers.String("container ID", afterTimerActionsData.containerID)}...)
			continue
		}
		containerData := containerDataInterface.(watchedContainerData)

		if config.GetConfigurationConfigContext().IsRelevantCVEServiceEnabled() && afterTimerActionsData.service == RelevantCVEsService {
			fileList := containerData.containerAggregator.GetContainerRealtimeFileList()

			if err = <-containerData.syncChannel[StepGetSBOM]; err != nil {
				logger.L().Ctx(context.GetBackgroundContext()).Debug("failed to get SBOM", []helpers.IDetails{helpers.String("container ID", afterTimerActionsData.containerID), helpers.String("container name", containerData.event.GetContainerName()), helpers.String("k8s resource ", containerData.event.GetK8SWorkloadID()), helpers.Error(err)}...)
				continue
			}
			if err = containerData.sbomClient.FilterSBOM(fileList); err != nil {
				ctx, span := otel.Tracer("").Start(containerData.ctx, "failed to filter SBOM", trace.WithAttributes(attribute.String("containerID", afterTimerActionsData.containerID), attribute.String("container workload", containerData.event.GetK8SWorkloadID())))
				logger.L().Ctx(ctx).Warning("failed to filter SBOM", []helpers.IDetails{helpers.String("container ID", afterTimerActionsData.containerID), helpers.String("container name", containerData.event.GetContainerName()), helpers.String("k8s resource", containerData.event.GetK8SWorkloadID()), helpers.Error(err)}...)
				span.End()
				continue
			}
			if err = containerData.sbomClient.StoreFilterSBOM(containerData.event.GetInstanceIDHash()); err != nil {
				if !errors.Is(err, sbom.IsAlreadyExist()) {
					ctx, span := otel.Tracer("").Start(containerData.ctx, "failed to store filter SBOM", trace.WithAttributes(attribute.String("containerID", afterTimerActionsData.containerID), attribute.String("container workload", containerData.event.GetK8SWorkloadID())))
					logger.L().Ctx(ctx).Error("failed to store filtered SBOM", []helpers.IDetails{helpers.String("container ID", afterTimerActionsData.containerID), helpers.String("k8s resource", containerData.event.GetK8SWorkloadID()), helpers.Error(err)}...)
					span.End()
				}
				continue
			}
			ctx, span := otel.Tracer("").Start(containerData.ctx, "SBOM store successfully", trace.WithAttributes(attribute.String("containerID", afterTimerActionsData.containerID), attribute.String("container workload", containerData.event.GetK8SWorkloadID())))
			logger.L().Ctx(ctx).Info("filtered SBOM has been stored successfully", []helpers.IDetails{helpers.String("containerID", afterTimerActionsData.containerID), helpers.String("k8s resource", containerData.event.GetK8SWorkloadID())}...)
			span.End()
		}
	}
}

func (ch *ContainerHandler) startTimer(watchedContainer watchedContainerData, containerID string) error {
	var err error
	select {
	case <-watchedContainer.snifferTicker.C:
		if config.GetConfigurationConfigContext().IsRelevantCVEServiceEnabled() {
			ch.afterTimerActionsChannel <- afterTimerActionsData{
				containerID: containerID,
				service:     RelevantCVEsService,
			}
		}
	case err = <-watchedContainer.syncChannel[StepEventAggregator]:
		if err.Error() == accumulator.DropEventOccurred {
			watchedContainer.snifferTicker.Stop()
			err = fmt.Errorf("droppedEvents.")
		} else if errors.Is(err, containerHasTerminatedError) {
			watchedContainer.snifferTicker.Stop()
			logger.L().Debug("container has terminated", helpers.String("container ID", watchedContainer.event.GetContainerID()), helpers.String("container name", watchedContainer.event.GetContainerName()), helpers.String("k8s resources", watchedContainer.event.GetK8SWorkloadID()))
		}
	}

	return err
}

func createTicker() *time.Ticker {
	return time.NewTicker(config.GetConfigurationConfigContext().GetUpdateDataPeriod())
}

func (ch *ContainerHandler) deleteResources(watchedContainer watchedContainerData, contEvent v1.ContainerEventData) {
	watchedContainer.snifferTicker.Stop()
	watchedContainer.containerAggregator.StopAggregate()
	watchedContainer.sbomClient.CleanResources()
	ch.watchedContainers.Delete(contEvent.GetContainerID())
}

func (ch *ContainerHandler) startRelevancyProcess(contEvent v1.ContainerEventData) {
	containerDataInterface, exist := ch.watchedContainers.Load(contEvent.GetContainerID())
	if !exist {
		logger.L().Ctx(context.GetBackgroundContext()).Error("startRelevancyProcess: failed to get container data", helpers.String("container ID", contEvent.GetContainerID()), helpers.String("container name", contEvent.GetContainerName()), helpers.String("k8s resources", contEvent.GetK8SWorkloadID()))
		return
	}
	watchedContainer := containerDataInterface.(watchedContainerData)

	ctx, span := otel.Tracer("").Start(context.GetBackgroundContext(), "container monitoring", trace.WithAttributes(attribute.String("containerID", contEvent.GetContainerID()), attribute.String("container workload", contEvent.GetK8SWorkloadID())))
	defer span.End()
	watchedContainer.ctx = ctx
	watchedContainer.span = span

	err := watchedContainer.containerAggregator.StartAggregate(watchedContainer.syncChannel[StepEventAggregator])
	if err != nil {
		return
	}

	now := time.Now()
	configStopTime := config.GetConfigurationConfigContext().GetSniffingMaxTimes()
	stopSniffingTime := now.Add(configStopTime)
	for start := time.Now(); start.Before(stopSniffingTime); {
		go ch.getSBOM(contEvent)
		err = ch.startTimer(watchedContainer, contEvent.GetContainerID())
		if err != nil {
			ctx, span := otel.Tracer("").Start(ctx, "dropped events.", trace.WithAttributes(attribute.String("containerID", contEvent.GetContainerID()), attribute.String("container workload", contEvent.GetK8SWorkloadID())))
			logger.L().Ctx(ctx).Warning("container monitoring got drop events - we may miss some realtime data", helpers.String("container ID", contEvent.GetContainerID()), helpers.String("container name", contEvent.GetContainerName()), helpers.String("k8s resources", contEvent.GetK8SWorkloadID()), helpers.Error(err))
			span.End()
		}
	}
	logger.L().Ctx(ctx).Info("stop monitor on container - after monitoring time", helpers.String("container ID", contEvent.GetContainerID()), helpers.String("container name", contEvent.GetContainerName()), helpers.String("k8s resources", contEvent.GetK8SWorkloadID()), helpers.Error(err))
	ch.deleteResources(watchedContainer, contEvent)
}

func getShortContainerID(containerID string) string {
	cont := strings.Split(containerID, "://")
	return cont[1][:12]
}

func (ch *ContainerHandler) getSBOM(contEvent v1.ContainerEventData) {
	containerDataInterface, exist := ch.watchedContainers.Load(contEvent.GetContainerID())
	if !exist {
		logger.L().Ctx(context.GetBackgroundContext()).Error("getSBOM: failed to get container data of ContainerID, not exist in memory", helpers.String("containerID", contEvent.GetContainerID()))
		return
	}
	watchedContainer := containerDataInterface.(watchedContainerData)
	imageHash, err := contEvent.GetImageHash()
	if err == nil {
		err = watchedContainer.sbomClient.GetSBOM(imageHash)
	}
	watchedContainer.syncChannel[StepGetSBOM] <- err
}

func (ch *ContainerHandler) handleContainerRunningEvent(contEvent v1.ContainerEventData) error {
	_, exist := ch.watchedContainers.Load(contEvent.GetContainerID())
	if exist {
		return containerAlreadyExistError
	}

	logger.L().Info("new container has loaded - start monitor it", []helpers.IDetails{helpers.String("ContainerID", contEvent.GetContainerID()), helpers.String("Container name", contEvent.GetContainerID()), helpers.String("k8s workload", contEvent.GetK8SWorkloadID())}...)
	newWatchedContainer := watchedContainerData{
		containerAggregator: CreateAggregator(getShortContainerID(contEvent.GetContainerID())),
		snifferTicker:       createTicker(),
		event:               contEvent,
		sbomClient:          sbom.CreateSBOMStorageClient(ch.storageClient, contEvent.GetK8SWorkloadID(), contEvent.GetImageID(), contEvent.GetInstanceID()),
		syncChannel: map[string]chan error{
			StepGetSBOM:         make(chan error, 10),
			StepEventAggregator: make(chan error, 10),
		},
	}
	ch.watchedContainers.Store(contEvent.GetContainerID(), newWatchedContainer)
	go ch.startRelevancyProcess(contEvent)
	return nil
}

func (ch *ContainerHandler) handleContainerTerminatedEvent(contEvent v1.ContainerEventData) error {
	watchedContainer, _ := ch.watchedContainers.Load(contEvent.GetContainerID())
	if watchedContainer != nil {
		data, ok := watchedContainer.(watchedContainerData)
		if !ok {
			return fmt.Errorf("failed to stop container ID %s", contEvent.GetContainerID())
		}
		data.syncChannel[StepEventAggregator] <- containerHasTerminatedError
	}
	return nil
}

func (ch *ContainerHandler) handleNewContainerEvent(contEvent v1.ContainerEventData) error {
	switch contEvent.GetContainerEventType() {
	case v1.ContainerRunning:
		return ch.handleContainerRunningEvent(contEvent)

	case v1.ContainerDeleted:
		return ch.handleContainerTerminatedEvent(contEvent)
	}
	return nil
}

func (ch *ContainerHandler) StartMainHandler() error {
	go ch.afterTimerActions()
	go ch.containerWatcher.StartWatchedOnContainers(ch.containersEventChan)

	for {
		contEvent := <-ch.containersEventChan
		err := ch.handleNewContainerEvent(contEvent)
		if err != nil {
			if !errors.Is(err, containerAlreadyExistError) {
				logger.L().Ctx(context.GetBackgroundContext()).Warning("fail to handle new container", helpers.String("ContainerID", contEvent.GetContainerID()), helpers.String("Container name", contEvent.GetContainerID()), helpers.String("k8s workload", contEvent.GetK8SWorkloadID()), helpers.Error(err))
			}
		}
	}
}
