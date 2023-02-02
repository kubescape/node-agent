package ebpf_engine

import (
	"strconv"
	"time"

	"sniffer/core/accumulator_data_structure"

	"github.com/slashben/kubescape-ebpf/core/common"
	fileaccessmonitor "github.com/slashben/kubescape-ebpf/core/file-access-monitor"
)

type ciliumEbpfEngineClient struct {
	eventChannel chan fileaccessmonitor.FileActivityEvent
}

type CiliumSnifferEngine struct {
	ebpfEngineClient           *fileaccessmonitor.FileActivityMonitor
	ciliumEbpfEngineClientData ciliumEbpfEngineClient
}

func CreateCiliumSnifferEngine() *CiliumSnifferEngine {
	client := ciliumEbpfEngineClient{
		eventChannel: make(chan fileaccessmonitor.FileActivityEvent),
	}
	return &CiliumSnifferEngine{
		ebpfEngineClient:           fileaccessmonitor.CreateFileActivityMonitor(&client),
		ciliumEbpfEngineClientData: client,
	}
}

func (ciliumSnifferEngine *CiliumSnifferEngine) StartSnifferEngine() error {
	ciliumSnifferEngine.ebpfEngineClient.Start()
	return nil
}

func parseTime(t uint64) (*time.Time, error) {
	time_str, err := strconv.ParseInt(strconv.FormatUint(t, 10), 10, 64)
	if err != nil {
		return nil, err
	}
	tm := time.Unix(time_str, 0)
	return &tm, nil
}

func parseEvent(event fileaccessmonitor.FileActivityEvent) (*accumulator_data_structure.SnifferEventData, error) {
	cid, err := common.GetContainerIdForNsMntId(event.NsMntId)
	if err != nil {
		return nil, err
	}

	t, err := parseTime(event.Timestamp)
	if err != nil {
		return nil, err
	}

	return &accumulator_data_structure.SnifferEventData{
		Timestamp:       *t,
		ContainerID:     cid[:12],
		SyscallCategory: "",
		SyscallType:     event.File,
		Ppid:            "",
		Pid:             strconv.Itoa(event.Pid),
		Exe:             event.Comm,
		Cmd:             "",
	}, nil
}

func (ciliumSnifferEngine *CiliumSnifferEngine) GetSnifferData(ebpfEngineDataChannel chan *accumulator_data_structure.SnifferEventData) {
	for {
		data, err := parseEvent(<-ciliumSnifferEngine.ciliumEbpfEngineClientData.eventChannel)
		if err != nil {
			continue
		}
		ebpfEngineDataChannel <- data
	}
}

func (client *ciliumEbpfEngineClient) Notify(event fileaccessmonitor.FileActivityEvent) {
	client.eventChannel <- event
}

func (ciliumSnifferEngine *CiliumSnifferEngine) GetEbpfEngineError() error {
	return nil
}
