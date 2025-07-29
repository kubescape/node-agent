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

func (e *EventWithChecks) CelEvaulationForm() (json.RawMessage, error) {
	data, err := json.Marshal(map[string]any{
		"event":          e.Event,
		"profile_checks": e.ProfileChecks.GetChecksAsMap(),
	})
	if err != nil {
		logger.L().Error("RuleManager - failed to marshal event", helpers.Error(err))
		return nil, err
	}
	return json.RawMessage(data), nil
}
