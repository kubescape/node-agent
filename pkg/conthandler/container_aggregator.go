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
		if newEvent.GetEventCMD() == accumulator.DROP_EVENT_OCCURRED {
			aggregator.StopAggregate()
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

func (aggregator *Aggregator) GetContainerRealtimeFileList() []string {
	var snifferRealtimeFileList []string

	// logger.Print(logger.DEBUG, false, "GetContainerRealtimeSyscalls: aggregator.aggregationData list size %d\n", len(aggregator.aggregationData))
	// logger.Print(logger.DEBUG, false, "GetContainerRealtimeSyscalls: aggregator.aggregationData list %v\n", aggregator.aggregationData)
	// if len(aggregator.aggregationData) > 0 {
	// logger.Print(logger.DEBUG, false, "GetContainerRealtimeSyscalls: aggregator.aggregationData event time range %v\n", aggregator.aggregationData[len(aggregator.aggregationData)-1].Timestamp.Sub(aggregator.aggregationData[0].Timestamp).Seconds())
	// }
	for i := range aggregator.aggregationData {
		fileName := aggregator.aggregationData[i].GetOpenFileName()
		if fileName != "" {
			snifferRealtimeFileList = append(snifferRealtimeFileList, fileName)
		}
	}

	// logger.Print(logger.DEBUG, false, "GetContainerRealtimeFileList: list size %d\n", len(snifferRealtimeFileList))
	// logger.Print(logger.DEBUG, false, "GetContainerRealtimeFileList: list %v\n", snifferRealtimeFileList)
	return snifferRealtimeFileList
}
