package conthandler

import (
	"fmt"
	"sniffer/pkg/config"
	v1 "sniffer/pkg/conthandler/v1"
	accumulator "sniffer/pkg/event_data_storage"
	"strings"
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
	syncChannel         map[string]chan error
}

type ContainerHandler struct {
	containerWatcher         *ContainerWatcher
	containersEventChan      chan v1.ContainerEventData
	watchedContainers        map[string]watchedContainerData
	afterTimerActionsChannel chan afterTimerActionsData
}

func CreateContainerHandler(contClient ContainerClient) (*ContainerHandler, error) {

	contWatcher, err := CreateContainerWatcher(contClient)
	if err != nil {
		return nil, err
	}

	return &ContainerHandler{
		containersEventChan:      make(chan v1.ContainerEventData, 50),
		containerWatcher:         contWatcher,
		watchedContainers:        make(map[string]watchedContainerData),
		afterTimerActionsChannel: make(chan afterTimerActionsData),
	}, nil
}

func (ch *ContainerHandler) afterTimerActions() error {
	var err error

	for {
		afterTimerActionsData := <-ch.afterTimerActionsChannel
		containerData := ch.watchedContainers[afterTimerActionsData.containerID]

		if config.GetConfigurationConfigContext().IsRelevantCVEServiceEnabled() && afterTimerActionsData.service == RELEVANT_CVES_SERVICE {
			_ = containerData.containerAggregator.GetContainerRealtimeFileList()
			if err = <-containerData.syncChannel[STEP_GET_SBOM]; err != nil {
				// logger.Print(logger.ERROR, false, "afterTimerActions: failed to get runtime file list with err %v\n", err)
				continue
			}
			// err = containerData.relaventCVEsData.sbomObject.FilterSbom(fileList)
			// if err != nil {
			// 	logger.Print(logger.ERROR, false, "afterTimerActions: failed to filter sbom with err %v\n", err)
			// 	continue
			// }
			// err = DB.SetDataInDB(containerData.relaventCVEsData.vulnObject.GetProcessedData(), nil, nil, "resourceName", afterTimerActionsData.service)
			// if err != nil {
			// 	logger.Print(logger.ERROR, false, "afterTimerActions: failed to set data in the DB with err %v\n", err)
			// 	continue
			// }
		}
	}
}

func (ch *ContainerHandler) startTimer(containerID string) error {
	var err error
	containerData := ch.watchedContainers[containerID]
	select {
	case <-containerData.snifferTimer.C:
		if config.GetConfigurationConfigContext().IsRelevantCVEServiceEnabled() {
			ch.afterTimerActionsChannel <- afterTimerActionsData{
				containerID: containerID,
				service:     RELEVANT_CVES_SERVICE,
			}
		}
	case err = <-containerData.syncChannel[STEP_EVENT_AGGREGATOR]:
		if err.Error() == accumulator.DROP_EVENT_OCCURRED {
			containerData.snifferTimer.Stop()
			err = fmt.Errorf("we have missed some kernel events, we are going to stop all current containers monitoring")
		}
	}

	return err
}

func createTimer() *time.Timer {
	return time.NewTimer(time.Duration(config.GetConfigurationConfigContext().GetUpdateDataPeriod()) * time.Minute)
}

func (ch *ContainerHandler) startRelevancyProcess(contID string, contData watchedContainerData) {
	err := contData.containerAggregator.StartAggregate(ch.watchedContainers[contID].syncChannel[STEP_EVENT_AGGREGATOR])
	if err != nil {
		contData.syncChannel[STEP_EVENT_AGGREGATOR] <- err
		return
	}

	stopSniffingTime := time.Now().Add(time.Duration(config.GetConfigurationConfigContext().GetSniffingMaxTimes()) * time.Minute)
	for start := time.Now(); start.Before(stopSniffingTime); {
		err = ch.startTimer(contID)
		if err != nil {
			logger.L().Warning("", helpers.Error(err))
			err = ch.watchedContainers[contID].containerAggregator.StopAggregate()
			if err != nil {
				logger.L().Warning("we have failed to stop to aggregate data for container ID: ", helpers.String("%s", contID))
			}
		}
	}
}

func getShortContainerID(containerID string) string {
	cont := strings.Split(containerID, "://")
	return cont[1][:12]
}

func (ch *ContainerHandler) handleContainerRunningEvent(contEvent v1.ContainerEventData) error {
	newWatchedContainer := watchedContainerData{
		containerAggregator: CreateAggregator(getShortContainerID(contEvent.GetContainerID())),
		snifferTimer:        createTimer(),
		syncChannel: map[string]chan error{
			STEP_GET_SBOM:         make(chan error, 10),
			STEP_EVENT_AGGREGATOR: make(chan error, 10),
		},
	}
	ch.watchedContainers[contEvent.GetContainerID()] = newWatchedContainer
	go ch.startRelevancyProcess(contEvent.GetContainerID(), newWatchedContainer)
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
