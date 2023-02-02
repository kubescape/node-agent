package ebpf_engine

type SnifferEngineClient interface {
	Notify(event interface{})
	GetSnifferData()
	GetEbpfEngineError() error
}
