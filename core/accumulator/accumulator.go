package accumulator

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"sniffer/core/accumulator_data_structure"
	"sniffer/core/config"
	"sniffer/core/ebpf_engine"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

type AccumulatorInterface interface {
	accumulateSnifferData()
}

type containersAccumalator struct {
	accumultorDataPerContainer map[string]chan accumulator_data_structure.SnifferEventData
	registerContainerState     bool
	unregisterContainerState   bool
	registerMutex              sync.Mutex
}

type CacheAccumulator struct {
	accumultorData                  []map[string][]accumulator_data_structure.SnifferEventData
	syncReaderWriterAccumulatorData sync.Mutex
	firstMapKeysOfAccumultorData    []string
	CacheAccumulatorSize            int
	mainDataChannel                 chan *accumulator_data_structure.SnifferEventData
	containersData                  containersAccumalator
	falcoEbpfEngine                 ebpf_engine.FalcoSnifferEngine
	ciliumEbpfEngine                ebpf_engine.CiliumSnifferEngine
}

type ContainerAccumulator struct {
	dataChannel chan accumulator_data_structure.SnifferEventData
	containerID string
}

var cacheAccumuator *CacheAccumulator

func CreateCacheAccumulator(CacheAccumulatorSize int) *CacheAccumulator {
	cacheAccumuator = &CacheAccumulator{
		CacheAccumulatorSize:         CacheAccumulatorSize,
		accumultorData:               make([]map[string][]accumulator_data_structure.SnifferEventData, CacheAccumulatorSize),
		firstMapKeysOfAccumultorData: make([]string, CacheAccumulatorSize),
		mainDataChannel:              make(chan *accumulator_data_structure.SnifferEventData),
		containersData: containersAccumalator{
			accumultorDataPerContainer: make(map[string]chan accumulator_data_structure.SnifferEventData),
			registerContainerState:     false,
			unregisterContainerState:   false,
		},
	}

	return cacheAccumuator
}

func CreateContainerAccumulator(containerID string, dataChannel chan accumulator_data_structure.SnifferEventData) *ContainerAccumulator {
	return &ContainerAccumulator{
		dataChannel: dataChannel,
		containerID: containerID,
	}
}

func (acc *CacheAccumulator) findIndexByTimestampWhenAccumultorDataIsFull(t time.Time) (int, bool) {
	index := 0
	minTimestamp := acc.accumultorData[0][acc.firstMapKeysOfAccumultorData[0]][0].Timestamp
	for i := range acc.accumultorData {
		if i == 0 {
			continue
		}
		if acc.accumultorData[i][acc.firstMapKeysOfAccumultorData[i]][0].Timestamp.Before(minTimestamp) {
			minTimestamp = acc.accumultorData[i][acc.firstMapKeysOfAccumultorData[i]][0].Timestamp
			index = i
		}
	}
	return index, true
}

func (acc *CacheAccumulator) findIndexByTimestamp(t time.Time) (int, bool) {
	for i := range acc.accumultorData {
		if len(acc.accumultorData[i]) == 0 {
			return i, true
		}
		firstKey := acc.firstMapKeysOfAccumultorData[i]
		if t.Sub((acc.accumultorData[i])[firstKey][0].Timestamp) < time.Second {
			return i, false
		}
	}
	index, createNewMap := acc.findIndexByTimestampWhenAccumultorDataIsFull(t)
	if index != -1 {
		return index, createNewMap
	}
	// logger.L().Debug("findIndexByTimestamp: failed to find index, sniffer data will not saved")
	return -1, false
}

func (acc *CacheAccumulator) accumulateSnifferData() {
	for {
		metadataAcc := <-acc.mainDataChannel
		logger.L().Info("metadataAcc ", helpers.String("", fmt.Sprintf("%v", metadataAcc)))
		if strings.Contains(metadataAcc.ContainerID, config.GetMyContainerID()) {
			continue
		}
		if metadataAcc != nil {
			if metadataAcc.Cmd == "drop event occured\n" {
				if acc.containersData.unregisterContainerState || acc.containersData.registerContainerState {
					acc.containersData.registerMutex.Lock()
				}
				if len(acc.containersData.accumultorDataPerContainer) > 0 {
					for contID := range acc.containersData.accumultorDataPerContainer {
						acc.containersData.accumultorDataPerContainer[contID] <- *metadataAcc
					}
				}
				if acc.containersData.unregisterContainerState || acc.containersData.registerContainerState {
					acc.containersData.registerMutex.Unlock()
				}
			} else {
				index, createNewMap := acc.findIndexByTimestamp(metadataAcc.Timestamp)
				if index == -1 {
					// logger.L().Debug("metadataAcc %v\n", metadataAcc)
					continue
				}
				acc.syncReaderWriterAccumulatorData.Lock()
				if createNewMap {
					slice := make([]accumulator_data_structure.SnifferEventData, 0)
					m := make(map[string][]accumulator_data_structure.SnifferEventData)
					m[metadataAcc.ContainerID] = slice
					acc.accumultorData[index] = m
					acc.firstMapKeysOfAccumultorData[index] = metadataAcc.ContainerID
				}
				a := acc.accumultorData[index]
				a[metadataAcc.ContainerID] = append(a[metadataAcc.ContainerID], *metadataAcc)
				acc.accumultorData[index][metadataAcc.ContainerID] = append(acc.accumultorData[index][metadataAcc.ContainerID], *metadataAcc)
				acc.syncReaderWriterAccumulatorData.Unlock()

				if acc.containersData.unregisterContainerState || acc.containersData.registerContainerState {
					acc.containersData.registerMutex.Lock()
				}
				if containerAccumalatorChan, exist := acc.containersData.accumultorDataPerContainer[metadataAcc.ContainerID]; exist {
					containerAccumalatorChan <- *metadataAcc
				}
				if acc.containersData.unregisterContainerState || acc.containersData.registerContainerState {
					acc.containersData.registerMutex.Unlock()
				}
			}
		}
	}
}

func (acc *CacheAccumulator) getSnifferData() {
	if config.IsFalcoEbpfEngine() {
		acc.falcoEbpfEngine.GetSnifferData(acc.mainDataChannel)
	} else {
		acc.ciliumEbpfEngine.GetSnifferData(acc.mainDataChannel)
	}
}

func (acc *CacheAccumulator) getEbpfEngineError(errChan chan error) {
	if config.IsFalcoEbpfEngine() {
		errChan <- acc.falcoEbpfEngine.GetEbpfEngineError()
	} else {
		errChan <- acc.ciliumEbpfEngine.GetEbpfEngineError()
	}
}

func (acc *CacheAccumulator) StartCacheAccumalator(errChan chan error, syscallFilter []string, includeHost bool, sniffMainThreadOnly bool) error {
	if config.IsFalcoEbpfEngine() {
		acc.falcoEbpfEngine = *ebpf_engine.CreateFalcoSnifferEngine(syscallFilter, includeHost, sniffMainThreadOnly, "")
		err := acc.falcoEbpfEngine.StartSnifferEngine()
		if err != nil {
			logger.L().Error("fail to create sniffer agent process\n")
			return err
		}
	} else {
		acc.ciliumEbpfEngine = *ebpf_engine.CreateCiliumSnifferEngine()
		err := acc.ciliumEbpfEngine.StartSnifferEngine()
		if err != nil {
			logger.L().Error("fail to create sniffer agent process")
			return err
		}
	}

	go acc.accumulateSnifferData()
	go acc.getSnifferData()
	go acc.getEbpfEngineError(errChan)
	return nil
}

func (acc *ContainerAccumulator) registerContainerAccumalator() {
	cacheAccumuator.containersData.registerContainerState = true
	cacheAccumuator.containersData.registerMutex.Lock()
	cacheAccumuator.containersData.accumultorDataPerContainer[acc.containerID] = acc.dataChannel
	cacheAccumuator.containersData.registerMutex.Unlock()
	cacheAccumuator.containersData.registerContainerState = false
}

func (acc *ContainerAccumulator) unregisterContainerAccumalator() {
	cacheAccumuator.containersData.unregisterContainerState = true
	cacheAccumuator.containersData.registerMutex.Lock()
	delete(cacheAccumuator.containersData.accumultorDataPerContainer, acc.containerID)
	cacheAccumuator.containersData.registerMutex.Unlock()
	cacheAccumuator.containersData.unregisterContainerState = false
}

func (acc *ContainerAccumulator) StartContainerAccumalator() {
	acc.registerContainerAccumalator()
}

func (acc *ContainerAccumulator) StopWatching() {
	acc.unregisterContainerAccumalator()
}

func GetCacheAccumaltor() *CacheAccumulator {
	return cacheAccumuator
}

func (acc *CacheAccumulator) AccumulatorByContainerID(aggregationData *[]accumulator_data_structure.SnifferEventData, containerID string, containerStartTime interface{}) {
	for i := range acc.accumultorData {
		logger.L().Debug("", helpers.String("index ", fmt.Sprintf("%d:%v", i, acc.accumultorData[i])))
	}
	for i := range acc.accumultorData {
		for j := range acc.accumultorData[i][containerID] {
			acc.syncReaderWriterAccumulatorData.Lock()
			*aggregationData = append(*aggregationData, acc.accumultorData[i][containerID][j])
			acc.syncReaderWriterAccumulatorData.Unlock()
		}
	}
	logger.L().Debug("data ", helpers.String("", fmt.Sprintf("%v", aggregationData)))
}
