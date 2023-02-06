package ebpfeng

import "sniffer/pkg/ebpfev"

type EbpfEngineClient interface {
	StartEbpfEngine() error
	GetData(chan *ebpfev.EventData)
	GetEbpfEngineError(chan error)
}
