package utils

import (
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

type UnshareEvent struct {
	BaseEvent
	ExePath    string
	UpperLayer *bool
}

func (e *UnshareEvent) GetExePath() string {
	if e.ExePath == "" {
		val, err := e.GetDatasource().GetField("exepath").String(e.GetData())
		if err != nil {
			logger.L().Warning("GetExePath - exepath field not found or invalid", helpers.String("eventType", string(e.EventType)))
			return ""
		}
		e.ExePath = val
	}
	return e.ExePath
}

func (e *UnshareEvent) GetUpperLayer() bool {
	if e.UpperLayer == nil {
		val, err := e.GetDatasource().GetField("upper_layer").Bool(e.GetData())
		if err != nil {
			logger.L().Warning("GetUpperLayer - upper_layer field not found or invalid", helpers.String("eventType", string(e.EventType)))
			return false
		}
		e.UpperLayer = &val
	}
	return *e.UpperLayer
}
