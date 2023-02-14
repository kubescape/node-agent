package accumulator

type AcccumulatorClient interface {
	// this function StartAccumulator will store the data from the ebpf engine
	StartAccumulator() error
	StartContainerAccumulator() error
	StopContainerAccumulator() error
}
