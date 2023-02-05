package ebpfeng

import "sniffer/pkg/ebpfev_v1"

type EbpfEngineClient interface {
	StartEbpfEngine() error
	GetData(chan *ebpfev_v1.EventData)
	GetEbpfEngineError(chan error)
}
