package accumulator

type AcccumulatorClient interface {
	// this function StartAccumulator will store the data from the ebpf engine
	GetAccumulator() error
	StartContainerAccumulator() error
	StopContainerAccumulator() error
}
