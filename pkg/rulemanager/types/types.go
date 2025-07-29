package types

import (
	"github.com/fatih/structs"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilevalidator"
	"github.com/kubescape/node-agent/pkg/utils"
)

type EventWithChecks struct {
	Event         utils.K8sEvent                           `json:"event"`
	ProfileChecks profilevalidator.ProfileValidationResult `json:"profile_checks"`
}

// CelEvaluationMap returns the data as map[string]any for direct CEL evaluation
func (e *EventWithChecks) CelEvaluationMap() map[string]any {
	eventMap := structs.Map(e.Event)

	if eventMap["Extra"] != nil {
		return map[string]any{
			"event":          eventMap["Event"],
			"profile_checks": e.ProfileChecks.GetChecksAsMap(),
		}
	}

	return map[string]any{
		"event":          eventMap,
		"profile_checks": e.ProfileChecks.GetChecksAsMap(),
	}
}
