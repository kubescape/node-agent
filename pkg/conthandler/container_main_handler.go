package conthandler

import (
	"fmt"
	"sniffer/pkg/config"
	v1 "sniffer/pkg/conthandler/v1"
	accumulator "sniffer/pkg/event_data_storage"
	"sniffer/pkg/sbom"
	"sniffer/pkg/storageclient"
	"strings"
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

const (
	RELEVANT_CVES_SERVICE = "RELEVANT_CVES_SERVICE"
	STEP_GET_SBOM         = "STEP_GET_SBOM"
	STEP_EVENT_AGGREGATOR = "STEP_EVENT_AGGREGATOR"
)

type supportedServices string

type afterTimerActionsData struct {
	containerID string
	service     supportedServices
}

type watchedContainerData struct {
	containerAggregator *Aggregator
	snifferTimer        *time.Timer
	event               v1.ContainerEventData
	syncChannel         map[string]chan error
	sbomClient          sbom.SBOMClient
}

type ContainerHandler struct {
	containerWatcher         *ContainerWatcher
	containersEventChan      chan v1.ContainerEventData
	watchedContainers        map[string]watchedContainerData
	syncWatchedContainersMap *sync.RWMutex
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
		watchedContainers:        make(map[string]watchedContainerData),
		syncWatchedContainersMap: &sync.RWMutex{},
		afterTimerActionsChannel: make(chan afterTimerActionsData, 50),
		storageClient:            storageClient,
	}, nil
}

func (ch *ContainerHandler) afterTimerActions() error {
	var err error

	for {
		afterTimerActionsData := <-ch.afterTimerActionsChannel
		ch.syncWatchedContainersMap.Lock()
		containerData := ch.watchedContainers[afterTimerActionsData.containerID]
		ch.syncWatchedContainersMap.Unlock()

		if config.GetConfigurationConfigContext().IsRelevantCVEServiceEnabled() && afterTimerActionsData.service == RELEVANT_CVES_SERVICE {
			fileList := containerData.containerAggregator.GetContainerRealtimeFileList()

			if err = <-containerData.syncChannel[STEP_GET_SBOM]; err != nil {
				logger.L().Warning("failed to get SBOM of containerID ", []helpers.IDetails{helpers.String("%s ", afterTimerActionsData.containerID), helpers.String("of k8s resource %s with err ", containerData.event.GetK8SWorkloadID()), helpers.Error(err)}...)
				continue
			}
			if err = containerData.sbomClient.FilterSBOM(afterTimerActionsData.containerID, fileList); err != nil {
				logger.L().Warning("failed to filter SBOM of containerID ", []helpers.IDetails{helpers.String("%s ", afterTimerActionsData.containerID), helpers.String("of k8s resource %s with err ", containerData.event.GetK8SWorkloadID()), helpers.Error(err)}...)
				continue
			}
			if err = containerData.sbomClient.StoreFilterSBOM(afterTimerActionsData.containerID); err != nil {
				if err.Error() == sbom.DataAlreadyExist {
					logger.L().Warning("SBOM of containerID ", []helpers.IDetails{helpers.String("%s ", afterTimerActionsData.containerID), helpers.String("of k8s resource %s already reported ", containerData.event.GetK8SWorkloadID())}...)
				} else {
					logger.L().Warning("failed to store filter SBOM of containerID ", []helpers.IDetails{helpers.String("%s ", afterTimerActionsData.containerID), helpers.String("of k8s resource %s with err ", containerData.event.GetK8SWorkloadID()), helpers.Error(err)}...)
				}
				continue
			}
			logger.L().Info("filtered SBOM of containerID ", []helpers.IDetails{helpers.String("%s ", afterTimerActionsData.containerID), helpers.String("of k8s resource %s has stored successfully in the storage", containerData.event.GetK8SWorkloadID())}...)
		}
	}
}

func (ch *ContainerHandler) startTimer(watchedContainer watchedContainerData, containerID string) error {
	var err error
	select {
	case <-watchedContainer.snifferTimer.C:
		if config.GetConfigurationConfigContext().IsRelevantCVEServiceEnabled() {
			ch.afterTimerActionsChannel <- afterTimerActionsData{
				containerID: containerID,
				service:     RELEVANT_CVES_SERVICE,
			}
		}
	case err = <-watchedContainer.syncChannel[STEP_EVENT_AGGREGATOR]:
		if err.Error() == accumulator.DROP_EVENT_OCCURRED {
			watchedContainer.snifferTimer.Stop()
			err = fmt.Errorf("we have missed some kernel events, we are going to stop all current containers monitoring")
		}
	}

	return err
}

func createTimer() *time.Timer {
	return time.NewTimer(time.Duration(config.GetConfigurationConfigContext().GetUpdateDataPeriod()) * time.Second)
}

func (ch *ContainerHandler) startRelevancyProcess(contEvent v1.ContainerEventData) {
	ch.syncWatchedContainersMap.Lock()
	watchedContainer := ch.watchedContainers[contEvent.GetContainerID()]
	ch.syncWatchedContainersMap.Unlock()

	err := watchedContainer.containerAggregator.StartAggregate(watchedContainer.syncChannel[STEP_EVENT_AGGREGATOR])
	if err != nil {
		return
	}

	now := time.Now()
	configStopTime := time.Duration(config.GetConfigurationConfigContext().GetSniffingMaxTimes())
	stopSniffingTime := now.Add(configStopTime * time.Minute)
	for start := time.Now(); start.Before(stopSniffingTime); {
		err = ch.startTimer(watchedContainer, contEvent.GetContainerID())
		if err != nil {
			logger.L().Warning("", helpers.Error(err))
			err = watchedContainer.containerAggregator.StopAggregate()
			if err != nil {
				logger.L().Warning("we have failed to stop to aggregate data for container ID: ", helpers.String("%s", contEvent.GetContainerID()))
			}
			ch.syncWatchedContainersMap.Lock()
			delete(ch.watchedContainers, contEvent.GetContainerID())
			ch.syncWatchedContainersMap.Unlock()

			break
		}
		watchedContainer.snifferTimer.Reset(time.Duration(config.GetConfigurationConfigContext().GetUpdateDataPeriod()) * time.Second)
	}
}

func getShortContainerID(containerID string) string {
	cont := strings.Split(containerID, "://")
	return cont[1][:12]
}

func (ch *ContainerHandler) getSBOM(contEvent v1.ContainerEventData) {
	ch.syncWatchedContainersMap.Lock()
	watchedContainer := ch.watchedContainers[contEvent.GetContainerID()]
	ch.syncWatchedContainersMap.Unlock()
	err := watchedContainer.sbomClient.GetSBOM(contEvent.GetContainerID())
	watchedContainer.syncChannel[STEP_GET_SBOM] <- err
}

func (ch *ContainerHandler) handleContainerRunningEvent(contEvent v1.ContainerEventData) error {
	newWatchedContainer := watchedContainerData{
		containerAggregator: CreateAggregator(getShortContainerID(contEvent.GetContainerID())),
		snifferTimer:        createTimer(),
		event:               contEvent,
		sbomClient:          sbom.CreateSBOMStorageClient(ch.storageClient),
		syncChannel: map[string]chan error{
			STEP_GET_SBOM:         make(chan error, 10),
			STEP_EVENT_AGGREGATOR: make(chan error, 10),
		},
	}
	ch.syncWatchedContainersMap.Lock()
	ch.watchedContainers[contEvent.GetContainerID()] = newWatchedContainer
	ch.syncWatchedContainersMap.Unlock()
	go ch.startRelevancyProcess(contEvent)
	go ch.getSBOM(contEvent)
	return nil
}

func (ch *ContainerHandler) handleNewContainerEvent(contEvent v1.ContainerEventData) error {
	switch contEvent.GetContainerEventType() {
	case v1.CONTAINER_RUNNING:
		return ch.handleContainerRunningEvent(contEvent)
	}
	return nil
}

func (ch *ContainerHandler) StartMainHandler() error {
	go ch.afterTimerActions()
	go ch.containerWatcher.StartWatchedOnContainers(ch.containersEventChan)

	for {
		contEvent := <-ch.containersEventChan
		logger.L().Info("", []helpers.IDetails{helpers.String("new container %s ", contEvent.GetContainerID()), helpers.String("has loaded in microservice %s", contEvent.GetK8SWorkloadID())}...)
		err := ch.handleNewContainerEvent(contEvent)
		if err != nil {
			logger.L().Warning("fail to handle new container %s was loaded, start monitor on it's container %s")
		}
	}
}
