package accumulator

type AcccumulatorClient interface {
	// this function StartCacheAccumulator will store the data from the ebpf engine
	StartCacheAccumulator() error
	StartContainerAccumulator() error
	StopContainerAccumulator() error
}
