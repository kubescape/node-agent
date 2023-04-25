package conthandler

import (
	"fmt"
	"sniffer/pkg/ebpfev/v1"
	accumulator "sniffer/pkg/event_data_storage"
)

type Aggregator struct {
	containerID          string
	aggregationData      []ebpfev.EventData
	aggregationDataChan  chan ebpfev.EventData
	containerAccumulator *accumulator.ContainerAccumulator
}

func CreateAggregator(containerID string) *Aggregator {
	return &Aggregator{
		containerID:          containerID,
		aggregationData:      make([]ebpfev.EventData, 0),
		aggregationDataChan:  make(chan ebpfev.EventData),
		containerAccumulator: nil,
	}
}

func (aggregator *Aggregator) collectDataFromContainerAccumulator(errChan chan error) {
	for {
		newEvent := <-aggregator.aggregationDataChan
		if newEvent.GetEventCMD() == accumulator.DropEventOccurred {
			_ = aggregator.StopAggregate()
			errChan <- fmt.Errorf(newEvent.GetEventCMD())
			break
		}
		aggregator.aggregationData = append(aggregator.aggregationData, newEvent)
	}
}

func (aggregator *Aggregator) aggregateFromCacheAccumulator() {
	accumulator.AccumulatorByContainerID(&aggregator.aggregationData, aggregator.containerID)
}

func (aggregator *Aggregator) StartAggregate(errChan chan error) error {
	aggregator.containerAccumulator = accumulator.CreateContainerAccumulator(aggregator.containerID, aggregator.aggregationDataChan)
	go aggregator.containerAccumulator.StartContainerAccumulator()
	go aggregator.collectDataFromContainerAccumulator(errChan)
	aggregator.aggregateFromCacheAccumulator()
	return nil
}

func (aggregator *Aggregator) StopAggregate() error {
	aggregator.containerAccumulator.StopContainerAccumulator()
	return nil
}

func (aggregator *Aggregator) GetContainerRealtimeFileList() map[string]bool {
	snifferRealtimeFileList := make(map[string]bool)

	for i := range aggregator.aggregationData {
		fileName := aggregator.aggregationData[i].GetOpenFileName()
		if fileName != "" {
			snifferRealtimeFileList[fileName] = true
		}
	}

	return snifferRealtimeFileList
}
