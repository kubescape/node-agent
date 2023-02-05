package accumulator

type AcccumulatorClient interface {
	StartCacheAccumulator() error
	StartContainerAccumalator() error
	StopContainerAccumulator() error
}
