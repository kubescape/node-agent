package utils

import (
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

type ForkEvent struct {
	BaseEvent
	ExePath string
}

func (e *ForkEvent) GetExePath() string {
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
