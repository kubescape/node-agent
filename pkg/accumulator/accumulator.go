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
	CACHE_ACCUMULATOR_SIZE = 10
)

type containersAccumulator struct {
	accumulatorDataPerContainer map[string]chan evData.EventData
	registerMutex               sync.Mutex
}

type CacheAccumulator struct {
	accumulatorData                 []map[string][]evData.EventData
	syncReaderWriterAccumulatorData sync.Mutex
	firstMapKeysOfAccumulatorData   []string
	cacheAccumulatorSize            int
	mainDataChannel                 chan *evData.EventData
	containersData                  containersAccumulator
	ebpfEngine                      ebpfeng.EbpfEngineClient
}

type ContainerAccumulator struct {
	dataChannel chan evData.EventData
	containerID string
}

var myContainerID string
var cacheAccumulator *CacheAccumulator

func CreateAccumulator() *CacheAccumulator {
	cacheAccumulator = &CacheAccumulator{
		cacheAccumulatorSize:          CACHE_ACCUMULATOR_SIZE,
		accumulatorData:               make([]map[string][]evData.EventData, CACHE_ACCUMULATOR_SIZE),
		firstMapKeysOfAccumulatorData: make([]string, CACHE_ACCUMULATOR_SIZE),
		mainDataChannel:               make(chan *evData.EventData),
		containersData: containersAccumulator{
			accumulatorDataPerContainer: make(map[string]chan evData.EventData),
		},
	}

	return cacheAccumulator
}

func CreateContainerAccumulator(containerID string, dataChannel chan evData.EventData) *ContainerAccumulator {
	return &ContainerAccumulator{
		dataChannel: dataChannel,
		containerID: containerID,
	}
}

func (acc *CacheAccumulator) createNewMap(event *evData.EventData, index int) {
	slice := make([]evData.EventData, 0)
	m := make(map[string][]evData.EventData)
	m[event.GetEventContainerID()] = slice
	acc.accumulatorData[index] = m
	acc.firstMapKeysOfAccumulatorData[index] = event.GetEventContainerID()
}

func (acc *CacheAccumulator) findIndexByTimestampWhenAccumulatorDataIsFull(event *evData.EventData) int {
	index := 0
	minTimestamp := acc.accumulatorData[0][acc.firstMapKeysOfAccumulatorData[0]][0].GetEventTimestamp()
	for i := range acc.accumulatorData {
		if i == 0 {
			continue
		}
		if acc.accumulatorData[i][acc.firstMapKeysOfAccumulatorData[i]][0].GetEventTimestamp().Before(minTimestamp) {
			minTimestamp = acc.accumulatorData[i][acc.firstMapKeysOfAccumulatorData[i]][0].GetEventTimestamp()
			index = i
		}
	}
	acc.createNewMap(event, index)
	return index
}

func (acc *CacheAccumulator) findIndexByTimestamp(event *evData.EventData) int {
	for i := range acc.accumulatorData {
		if len(acc.accumulatorData[i]) == 0 {
			acc.createNewMap(event, i)
			return i
		}
		firstKey := acc.firstMapKeysOfAccumulatorData[i]
		if event.GetEventTimestamp().Sub((acc.accumulatorData[i])[firstKey][0].GetEventTimestamp()) < time.Second {
			return i
		}
	}
	index := acc.findIndexByTimestampWhenAccumulatorDataIsFull(event)
	if index != -1 {
		return index
	}
	// logger.L().Debug("findIndexByTimestamp: failed to find index, sniffer data will not saved")
	return -1
}

func (acc *CacheAccumulator) removeAllStreamedContainers(event *evData.EventData) {
	acc.containersData.registerMutex.Lock()
	if len(acc.containersData.accumulatorDataPerContainer) > 0 {
		for contID := range acc.containersData.accumulatorDataPerContainer {
			acc.containersData.accumulatorDataPerContainer[contID] <- *event
		}
	}
	acc.containersData.registerMutex.Unlock()
}

func (acc *CacheAccumulator) addEventToCacheAccumulator(event *evData.EventData, index int) {
	acc.syncReaderWriterAccumulatorData.Lock()
	a := acc.accumulatorData[index]
	a[event.GetEventContainerID()] = append(a[event.GetEventContainerID()], *event)
	acc.accumulatorData[index][event.GetEventContainerID()] = append(acc.accumulatorData[index][event.GetEventContainerID()], *event)
	acc.syncReaderWriterAccumulatorData.Unlock()
}

func (acc *CacheAccumulator) streamEventToRegisterContainer(event *evData.EventData, index int) {
	acc.containersData.registerMutex.Lock()
	if containerAccumulatorChan, exist := acc.containersData.accumulatorDataPerContainer[event.GetEventContainerID()]; exist {
		containerAccumulatorChan <- *event
	}
	acc.containersData.registerMutex.Unlock()
}

func (acc *CacheAccumulator) accumulateEbpfEngineData() {
	for {
		event := <-acc.mainDataChannel
		logger.L().Debug("metadataAcc ", helpers.String("", fmt.Sprintf("%v", event)))
		if strings.Contains(event.GetEventContainerID(), myContainerID) {
			continue
		}
		if event != nil {
			if event.GetEventCMD() == "drop event occurred\n" {
				acc.removeAllStreamedContainers(event)
			} else {
				index := acc.findIndexByTimestamp(event)
				if index == -1 {
					// logger.L().Debug("metadataAcc %v\n", metadataAcc)
					continue
				}
				acc.addEventToCacheAccumulator(event, index)
				acc.streamEventToRegisterContainer(event, index)
			}
		}
	}
}

func (acc *CacheAccumulator) getEbpfEngineData() {
	acc.ebpfEngine.GetData(acc.mainDataChannel)
}

func (acc *CacheAccumulator) getEbpfEngineError(errChan chan error) {
	errChan <- acc.ebpfEngine.GetEbpfEngineError()
}

func (acc *CacheAccumulator) StartAccumulator(errChan chan error) error {
	falcoEbpfEngine := ebpfeng.CreateFalcoEbpfEngine(config.GetConfigurationConfigContext().GetSyscallFilter(), false, false, "")
	acc.ebpfEngine = falcoEbpfEngine

	err := acc.ebpfEngine.StartEbpfEngine()
	if err != nil {
		logger.L().Error("fail to create ebpf engine")
		return err
	}

	go acc.accumulateEbpfEngineData()
	go acc.getEbpfEngineData()
	go acc.getEbpfEngineError(errChan)
	return nil
}

func (acc *ContainerAccumulator) registerContainerAccumulator() {
	cacheAccumulator.containersData.registerMutex.Lock()
	cacheAccumulator.containersData.accumulatorDataPerContainer[acc.containerID] = acc.dataChannel
	cacheAccumulator.containersData.registerMutex.Unlock()
}

func (acc *ContainerAccumulator) unregisterContainerAccumulator() {
	cacheAccumulator.containersData.registerMutex.Lock()
	delete(cacheAccumulator.containersData.accumulatorDataPerContainer, acc.containerID)
	cacheAccumulator.containersData.registerMutex.Unlock()
}

func (acc *ContainerAccumulator) StartContainerAccumulator() {
	acc.registerContainerAccumulator()
}

func (acc *ContainerAccumulator) StopContainerAccumulator() {
	acc.unregisterContainerAccumulator()
}

func GetCacheAccumulator() *CacheAccumulator {
	return cacheAccumulator
}

func (acc *CacheAccumulator) AccumulatorByContainerID(aggregationData *[]evData.EventData, containerID string, containerStartTime interface{}) {
	for i := range acc.accumulatorData {
		logger.L().Debug("", helpers.String("index ", fmt.Sprintf("%d:%v", i, acc.accumulatorData[i])))
	}
	for i := range acc.accumulatorData {
		for j := range acc.accumulatorData[i][containerID] {
			acc.syncReaderWriterAccumulatorData.Lock()
			*aggregationData = append(*aggregationData, acc.accumulatorData[i][containerID][j])
			acc.syncReaderWriterAccumulatorData.Unlock()
		}
	}
	logger.L().Debug("data ", helpers.String("", fmt.Sprintf("%v", aggregationData)))
}

func SetMyContainerID(mycid string) {
	myContainerID = mycid
}
