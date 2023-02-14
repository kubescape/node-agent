package ebpfeng

import ebpfev "sniffer/pkg/ebpfev/v1"

type EbpfEngineClient interface {
	StartEbpfEngine() error
	GetData(chan *ebpfev.EventData)
	GetEbpfEngineError() error
}
