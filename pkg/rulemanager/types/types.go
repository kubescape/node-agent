package types

import (
	"github.com/kubescape/node-agent/pkg/rulemanager/profilevalidator"
	"github.com/kubescape/node-agent/pkg/utils"
)

type EventWithChecks struct {
	Event         utils.K8sEvent                           `json:"event"`
	ProfileChecks profilevalidator.ProfileValidationResult `json:"profile_checks"`
}

// CelEvaluationMap returns the data as map[string]any for direct CEL evaluation
func (e *EventWithChecks) CelEvaluationMap() map[string]any {
	return map[string]any{
		"event":          e.Event,
		"profile_checks": e.ProfileChecks.GetChecksAsMap(),
	}
}
