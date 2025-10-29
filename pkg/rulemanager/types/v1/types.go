package types

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Rules struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec RulesSpec `json:"spec,omitempty"`
}

type RulesSpec struct {
	Rules []Rule `json:"rules" yaml:"rules"`
}

type Rule struct {
	Enabled                 bool                       `json:"enabled" yaml:"enabled"`
	ID                      string                     `json:"id" yaml:"id"`
	Name                    string                     `json:"name" yaml:"name"`
	Description             string                     `json:"description" yaml:"description"`
	Expressions             RuleExpressions            `json:"expressions" yaml:"expressions"`
	ProfileDependency       apitypes.ProfileDependency `json:"profile_dependency" yaml:"profile_dependency"`
	Severity                int                        `json:"severity" yaml:"severity"`
	SupportPolicy           bool                       `json:"support_policy" yaml:"support_policy"`
	Tags                    []string                   `json:"tags" yaml:"tags"`
	State                   map[string]any             `json:"state,omitempty" yaml:"state,omitempty"`
	AgentVersionRequirement string                     `json:"agent_version_requirement" yaml:"agent_version_requirement"`
}

type RuleExpressions struct {
	Message        string           `json:"message" yaml:"message"`
	UniqueID       string           `json:"unique_id" yaml:"unique_id"`
	RuleExpression []RuleExpression `json:"rule_expression" yaml:"rule_expression"`
}

type RuleExpression struct {
	EventType  utils.EventType `json:"event_type" yaml:"event_type"`
	Expression string          `json:"expression" yaml:"expression"`
}
