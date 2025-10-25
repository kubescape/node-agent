package utils

import (
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

type CapabilitiesEvent struct {
	BaseEvent
	Capability string
	Syscall    string
}

func (e *CapabilitiesEvent) GetCapability() string {
	if e.Capability == "" {
		val, err := e.GetDatasource().GetField("cap").String(e.GetData())
		if err != nil {
			logger.L().Warning("GetCapability - cap field not found or invalid", helpers.String("eventType", string(e.EventType)))
			return ""
		}
		e.Capability = val
	}
	return e.Capability
}

func (e *CapabilitiesEvent) GetSyscall() string {
	if e.Syscall == "" {
		val, err := e.GetDatasource().GetField("syscall").String(e.GetData())
		if err != nil {
			logger.L().Warning("GetSyscall - syscall field not found or invalid", helpers.String("eventType", string(e.EventType)))
			return ""
		}
		e.Syscall = val
	}
	return e.Syscall
}
