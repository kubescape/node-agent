package types

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/utils"
)

type Rule struct {
	Enabled           bool                       `json:"enabled"`
	ID                string                     `json:"id"`
	Name              string                     `json:"name"`
	Expressions       RuleExpressions            `json:"expressions"`
	ProfileDependency apitypes.ProfileDependency `json:"profile_dependency"`
	Severity          int                        `json:"severity"`
	SupportPolicy     bool                       `json:"support_policy"`
	Tags              []string                   `json:"tags"`
	State             map[string]any             `json:"state"`
}

type RuleExpressions struct {
	Message        string           `json:"message"`
	UniqueID       string           `json:"unique_id"`
	RuleExpression []RuleExpression `json:"rule_expression"`
}

type RuleExpression struct {
	EventType  utils.EventType `json:"event_type"`
	Expression string          `json:"expression"`
}
