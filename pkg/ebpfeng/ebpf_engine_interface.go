package ebpfeng

type EbpfEngineClient interface {
	StartEbpfEngine() error
	GetEbpfEngineData(chan *ebpfev.EventData)
	GetEbpfEngineError(chan error)
}
