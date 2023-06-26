package accumulator

type AccumulatorClient interface {
	StartContainerAccumulator()
	StopContainerAccumulator()
}
