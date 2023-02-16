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
	ACCUMULATOR_SIZE = 10
)

const (
	DROP_EVENT_OCCURRED = "drop event occurred\n"
)

type containersAccumulator struct {
	accumulatorDataPerContainer map[string]chan evData.EventData
	registerMutex               sync.Mutex
}

type Accumulator struct {
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
var accumulatorSingelton *Accumulator
var lock = &sync.Mutex{}

func createAccumulator() *Accumulator {
	myContainerID = "111111"
	accumulatorSingelton = &Accumulator{
		cacheAccumulatorSize:          ACCUMULATOR_SIZE,
		accumulatorData:               make([]map[string][]evData.EventData, ACCUMULATOR_SIZE),
		firstMapKeysOfAccumulatorData: make([]string, ACCUMULATOR_SIZE),
		mainDataChannel:               make(chan *evData.EventData),
		containersData: containersAccumulator{
			accumulatorDataPerContainer: make(map[string]chan evData.EventData),
		},
	}

	return accumulatorSingelton
}

func GetAccumulator() *Accumulator {
	if accumulatorSingelton == nil {
		lock.Lock()
		defer lock.Unlock()
		if accumulatorSingelton == nil {
			logger.L().Debug("Creating accumulatorSingelton now.")
			accumulatorSingelton = createAccumulator()
		} else {
			logger.L().Debug("accumulatorSingelton already created.")
		}
	} else {
		logger.L().Debug("accumulatorSingelton already created.")
	}

	return accumulatorSingelton
}

func CreateContainerAccumulator(containerID string, dataChannel chan evData.EventData) *ContainerAccumulator {
	return &ContainerAccumulator{
		dataChannel: dataChannel,
		containerID: containerID,
	}
}

func (acc *Accumulator) createNewMap(event *evData.EventData, index int) {
	slice := make([]evData.EventData, 0)
	m := make(map[string][]evData.EventData)
	m[event.GetEventContainerID()] = slice
	acc.accumulatorData[index] = m
	acc.firstMapKeysOfAccumulatorData[index] = event.GetEventContainerID()
}

func (acc *Accumulator) getFirstTimestamp() (time.Time, error) {
	if len(acc.accumulatorData) < 1 {
		return time.Time{}, fmt.Errorf("getFirstTimestamp failed the slice accumulatorData has no members")
	}
	if len(acc.firstMapKeysOfAccumulatorData) < 1 {
		return time.Time{}, fmt.Errorf("getFirstTimestamp failed the slice firstMapKeysOfAccumulatorData has no members")
	}
	if len(acc.accumulatorData[0][acc.firstMapKeysOfAccumulatorData[0]]) < 1 {
		return time.Time{}, fmt.Errorf("getFirstTimestamp failed the slice acc.accumulatorData[0][acc.firstMapKeysOfAccumulatorData[0] has no members")
	}
	return acc.accumulatorData[0][acc.firstMapKeysOfAccumulatorData[0]][0].GetEventTimestamp(), nil
}

func (acc *Accumulator) findIndexByTimestampWhenAccumulatorDataIsFull(event *evData.EventData) int {
	index := 0
	minTimestamp, err := acc.getFirstTimestamp()
	if err != nil {
		logger.L().Warning("findIndexByTimestampWhenAccumulatorDataIsFull fail to find the place to insert the event, fail with error", helpers.Error(err))
		return -1
	}
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

func (acc *Accumulator) findIndexByTimestamp(event *evData.EventData) int {
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
	return acc.findIndexByTimestampWhenAccumulatorDataIsFull(event)
}

func (acc *Accumulator) removeAllStreamedContainers(event *evData.EventData) {
	acc.containersData.registerMutex.Lock()
	if len(acc.containersData.accumulatorDataPerContainer) > 0 {
		for contID := range acc.containersData.accumulatorDataPerContainer {
			acc.containersData.accumulatorDataPerContainer[contID] <- *event
		}
	}
	acc.containersData.registerMutex.Unlock()
}

func (acc *Accumulator) addEventToCacheAccumulator(event *evData.EventData, index int) {
	acc.syncReaderWriterAccumulatorData.Lock()
	a := acc.accumulatorData[index]
	a[event.GetEventContainerID()] = append(a[event.GetEventContainerID()], *event)
	acc.accumulatorData[index][event.GetEventContainerID()] = append(acc.accumulatorData[index][event.GetEventContainerID()], *event)
	acc.syncReaderWriterAccumulatorData.Unlock()
}

func (acc *Accumulator) streamEventToRegisterContainer(event *evData.EventData, index int) {
	acc.containersData.registerMutex.Lock()
	if containerAccumulatorChan, exist := acc.containersData.accumulatorDataPerContainer[event.GetEventContainerID()]; exist {
		containerAccumulatorChan <- *event
	}
	acc.containersData.registerMutex.Unlock()
}

func (acc *Accumulator) accumulateEbpfEngineData() {
	for {
		event := <-acc.mainDataChannel
		logger.L().Debug("metadataAcc ", helpers.String("", fmt.Sprintf("%v", event)))
		if strings.Contains(event.GetEventContainerID(), myContainerID) {
			continue
		}
		if event != nil {
			if event.GetEventCMD() == DROP_EVENT_OCCURRED {
				acc.removeAllStreamedContainers(event)
			} else {
				index := acc.findIndexByTimestamp(event)
				if index == -1 {
					continue
				}
				acc.addEventToCacheAccumulator(event, index)
				acc.streamEventToRegisterContainer(event, index)
			}
		}
	}
}

func (acc *Accumulator) getEbpfEngineData() {
	acc.ebpfEngine.GetData(acc.mainDataChannel)
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
	accumulatorSingelton.containersData.registerMutex.Lock()
	accumulatorSingelton.containersData.accumulatorDataPerContainer[acc.containerID] = acc.dataChannel
	accumulatorSingelton.containersData.registerMutex.Unlock()
}

func (acc *ContainerAccumulator) unregisterContainerAccumulator() {
	accumulatorSingelton.containersData.registerMutex.Lock()
	delete(accumulatorSingelton.containersData.accumulatorDataPerContainer, acc.containerID)
	accumulatorSingelton.containersData.registerMutex.Unlock()
}

func (acc *ContainerAccumulator) StartContainerAccumulator() {
	acc.registerContainerAccumulator()
}

func (acc *ContainerAccumulator) StopContainerAccumulator() {
	acc.unregisterContainerAccumulator()
}

func GetCacheAccumulator() *Accumulator {
	return accumulatorSingelton
}

func (acc *Accumulator) AccumulatorByContainerID(aggregationData *[]evData.EventData, containerID string) {
	for i := range acc.accumulatorData {
		logger.L().Debug("", helpers.String("accumulatorData in index ", fmt.Sprintf("%d:%v", i, acc.accumulatorData[i])))
	}
	for i := range acc.accumulatorData {
		for j := range acc.accumulatorData[i][containerID] {
			acc.syncReaderWriterAccumulatorData.Lock()
			*aggregationData = append(*aggregationData, acc.accumulatorData[i][containerID][j])
			acc.syncReaderWriterAccumulatorData.Unlock()
		}
	}
	logger.L().Debug("full aggregation data ", helpers.String("of conatinerID ", fmt.Sprintf("%s is:", containerID)))
	logger.L().Debug("", helpers.String("", fmt.Sprintf("%v", aggregationData)))
}

func SetMyContainerID(mycid string) {
	myContainerID = mycid
}
