package types

import (
	"encoding/json"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilevalidator"
	"github.com/kubescape/node-agent/pkg/utils"
)

type EventWithChecks struct {
	Event         utils.K8sEvent                           `json:"event"`
	ProfileChecks profilevalidator.ProfileValidationResult `json:"profile_checks"`
}

func (e *EventWithChecks) CelEvaulationForm() map[string][]byte {
	serializedEvent, err := json.Marshal(e.Event)
	if err != nil {
		logger.L().Error("RuleManager - failed to marshal event", helpers.Error(err))
		return nil
	}

	serializedProfileChecks, err := json.Marshal(e.ProfileChecks)
	if err != nil {
		logger.L().Error("RuleManager - failed to marshal profile checks", helpers.Error(err))
		return nil
	}

	return map[string][]byte{
		"event":          serializedEvent,
		"profile_checks": serializedProfileChecks,
	}
}
