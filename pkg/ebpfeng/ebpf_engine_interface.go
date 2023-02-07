package ebpfeng

import ebpfev "sniffer/pkg/ebpfev/v1"

type EbpfEngineClient interface {
	StartEbpfEngine(chan error) error
	GetData(chan *ebpfev.EventData)
	GetEbpfEngineError() error
}
