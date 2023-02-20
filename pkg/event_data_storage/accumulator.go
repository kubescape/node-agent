package accumulator

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"sniffer/pkg/config"
	"sniffer/pkg/ebpfeng"
	evData "sniffer/pkg/ebpfev/v1"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

const (
	AccumulatorSize     = 10
	DROP_EVENT_OCCURRED = "drop event occurred\n"
)

type containersEventStreamer struct {
	streamDataChannelForContainerID map[string]chan evData.EventData
	registerMutex                   sync.Mutex
}

type Accumulator struct {
	data                            []map[string][]evData.EventData
	syncReaderWriterData            sync.RWMutex
	listOfFirstKeysInsertInEachSlot []string
	cacheSize                       int
	eventChannel                    chan *evData.EventData
	containersData                  containersEventStreamer
	ebpfEngine                      ebpfeng.EbpfEngineClient
}

type ContainerAccumulator struct {
	dataChannel chan evData.EventData
	containerID string
}

var nodeAgentContainerID string
var accumulatorInstance *Accumulator
var accumulatorInstanceLock = &sync.Mutex{}

func newAccumulator() *Accumulator {
	accumulatorInstance = &Accumulator{
		cacheSize:                       AccumulatorSize,
		data:                            make([]map[string][]evData.EventData, AccumulatorSize),
		listOfFirstKeysInsertInEachSlot: make([]string, AccumulatorSize),
		eventChannel:                    make(chan *evData.EventData),
		containersData: containersEventStreamer{
			streamDataChannelForContainerID: make(map[string]chan evData.EventData),
		},
	}

	return accumulatorInstance
}

func GetAccumulator() *Accumulator {
	if accumulatorInstance == nil {
		accumulatorInstanceLock.Lock()
		defer accumulatorInstanceLock.Unlock()
		if accumulatorInstance == nil {
			logger.L().Debug("Creating accumulatorInstance now.")
			accumulatorInstance = newAccumulator()
		}
	}

	return accumulatorInstance
}

func CreateContainerAccumulator(containerID string, dataChannel chan evData.EventData) *ContainerAccumulator {
	return &ContainerAccumulator{
		dataChannel: dataChannel,
		containerID: containerID,
	}
}

func (acc *Accumulator) createNewSlotInIndex(event *evData.EventData, index int) {
	slice := make([]evData.EventData, 0)
	m := make(map[string][]evData.EventData)
	m[event.GetEventContainerID()] = slice
	acc.data[index] = m
	acc.listOfFirstKeysInsertInEachSlot[index] = event.GetEventContainerID()
}

func (acc *Accumulator) getFirstTimestamp() (time.Time, error) {
	if len(acc.data) < 1 {
		return time.Time{}, fmt.Errorf("getFirstTimestamp failed the slice data has no members")
	}
	if len(acc.listOfFirstKeysInsertInEachSlot) < 1 {
		return time.Time{}, fmt.Errorf("getFirstTimestamp failed the slice that store the first data key in the accumulator has no members")
	}
	if len(acc.data[0][acc.listOfFirstKeysInsertInEachSlot[0]]) < 1 {
		return time.Time{}, fmt.Errorf("getFirstTimestamp failed the slice of events in the accumulator has no members")
	}
	return acc.data[0][acc.listOfFirstKeysInsertInEachSlot[0]][0].GetEventTimestamp(), nil
}

func (acc *Accumulator) findIndexByTimestampWhenAccumulatorDataIsFull(event *evData.EventData) (int, bool, error) {
	index := 0
	minTimestamp, err := acc.getFirstTimestamp()
	if err != nil {
		return -1, false, err
	}
	for i := 1; i < len(acc.data); i++ {
		if acc.data[i][acc.listOfFirstKeysInsertInEachSlot[i]][0].GetEventTimestamp().Before(minTimestamp) {
			minTimestamp = acc.data[i][acc.listOfFirstKeysInsertInEachSlot[i]][0].GetEventTimestamp()
			index = i
		}
	}
	return index, true, nil
}

func (acc *Accumulator) findIndexByTimestamp(event *evData.EventData) (int, bool, error) {
	for i := range acc.data {
		if len(acc.data[i]) == 0 {
			return i, true, nil
		}
		if i < len(acc.listOfFirstKeysInsertInEachSlot) {
			firstKey := acc.listOfFirstKeysInsertInEachSlot[i]
			if event.GetEventTimestamp().Sub((acc.data[i])[firstKey][0].GetEventTimestamp()) < time.Second {
				return i, false, nil
			}
		} else {
			return -1, false, fmt.Errorf("findIndexByTimestamp: trying to access slice of first accumulator keys to index out of range")
		}
	}
	return acc.findIndexByTimestampWhenAccumulatorDataIsFull(event)
}

func (acc *Accumulator) removeAllStreamedContainers(event *evData.EventData) {
	acc.containersData.registerMutex.Lock()
	defer acc.containersData.registerMutex.Unlock()
	if len(acc.containersData.streamDataChannelForContainerID) > 0 {
		for contID := range acc.containersData.streamDataChannelForContainerID {
			acc.containersData.streamDataChannelForContainerID[contID] <- *event
		}
	}
}

func (acc *Accumulator) addEventToCache(event *evData.EventData, index int) {
	acc.syncReaderWriterData.Lock()
	defer acc.syncReaderWriterData.Unlock()
	acc.data[index][event.GetEventContainerID()] = append(acc.data[index][event.GetEventContainerID()], *event)
}

func (acc *Accumulator) streamEventToRegisterContainer(event *evData.EventData) {
	acc.containersData.registerMutex.Lock()
	defer acc.containersData.registerMutex.Unlock()
	if containerAccumulatorChan, exist := acc.containersData.streamDataChannelForContainerID[event.GetEventContainerID()]; exist {
		containerAccumulatorChan <- *event
	}
}

/*
	accumulateEbpfEngineData get events from the ebpf engine and insert them into 2 place in memory:
	1. store event in the accumulator (the accumulator has a memory of the last 10 seconds of events - order'd by containerIDs)
	2. stream the event into channel of any new container
*/

func (acc *Accumulator) accumulateEbpfEngineData() {
	for {
		event := <-acc.eventChannel
		if nodeAgentContainerID != "" && strings.Contains(event.GetEventContainerID(), nodeAgentContainerID) {
			continue
		}
		if event != nil {
			if event.GetEventCMD() == DROP_EVENT_OCCURRED {
				acc.removeAllStreamedContainers(event)
			} else {
				index, newSlotIsNeeded, err := acc.findIndexByTimestamp(event)
				if err != nil {
					logger.L().Warning("findIndexByTimestamp fail to find the index to insert the event, fail with error", helpers.Error(err))
					logger.L().Warning("event that didn't store ", helpers.String("", fmt.Sprintf("%v", event)))
					continue
				}
				if newSlotIsNeeded {
					acc.createNewSlotInIndex(event, index)
				}
				acc.addEventToCache(event, index)
				acc.streamEventToRegisterContainer(event)
			}
		}
	}
}

func (acc *Accumulator) getEbpfEngineData() {
	acc.ebpfEngine.GetData(acc.eventChannel)
}

func (acc *Accumulator) getEbpfEngineError(errChan chan error) {
	errChan <- acc.ebpfEngine.GetEbpfEngineError()
}

func (acc *Accumulator) StartAccumulator(errChan chan error) error {
	falcoEbpfEngine := ebpfeng.CreateFalcoEbpfEngine(config.GetConfigurationConfigContext().GetSyscallFilter(), false, false, "")
	acc.ebpfEngine = falcoEbpfEngine

	err := acc.ebpfEngine.StartEbpfEngine()
	if err != nil {
		logger.L().Error("fail to create ebpf engine %v", helpers.Error(err))
		return err
	}

	go acc.accumulateEbpfEngineData()
	go acc.getEbpfEngineData()
	go acc.getEbpfEngineError(errChan)
	return nil
}

func (acc *ContainerAccumulator) registerContainerAccumulator() {
	accumulatorInstance.containersData.registerMutex.Lock()
	defer accumulatorInstance.containersData.registerMutex.Unlock()
	accumulatorInstance.containersData.streamDataChannelForContainerID[acc.containerID] = acc.dataChannel
}

func (acc *ContainerAccumulator) unregisterContainerAccumulator() {
	accumulatorInstance.containersData.registerMutex.Lock()
	defer accumulatorInstance.containersData.registerMutex.Unlock()
	delete(accumulatorInstance.containersData.streamDataChannelForContainerID, acc.containerID)
}

func (acc *ContainerAccumulator) StartContainerAccumulator() {
	acc.registerContainerAccumulator()
}

func (acc *ContainerAccumulator) StopContainerAccumulator() {
	acc.unregisterContainerAccumulator()
}

func GetCacheAccumulator() *Accumulator {
	return accumulatorInstance
}

func (acc *Accumulator) AccumulatorByContainerID(aggregationData *[]evData.EventData, containerID string) {
	acc.syncReaderWriterData.Lock()
	defer acc.syncReaderWriterData.Unlock()
	for i := range acc.data {
		logger.L().Debug("", helpers.String("data in index ", fmt.Sprintf("%d:%v", i, acc.data[i])))
	}
	for i := range acc.data {
		for j := range acc.data[i][containerID] {
			*aggregationData = append(*aggregationData, acc.data[i][containerID][j])
		}
	}
	logger.L().Debug("full aggregation data ", helpers.String("of containerID ", fmt.Sprintf("%s is: : aggregationData %v ", containerID, aggregationData)))
}

func SetMyContainerID(mycid string) {
	nodeAgentContainerID = mycid
}
