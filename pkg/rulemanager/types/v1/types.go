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
	ProfileDependency       apitypes.ProfileDependency `json:"profileDependency" yaml:"profileDependency"`
	Severity                int                        `json:"severity" yaml:"severity"`
	SupportPolicy           bool                       `json:"supportPolicy" yaml:"supportPolicy"`
	Tags                    []string                   `json:"tags" yaml:"tags"`
	ExecutionContexts       []string                   `json:"executionContexts" yaml:"executionContexts"` // kubernetes, host, standalone
	State                   map[string]any             `json:"state,omitempty" yaml:"state,omitempty"`
	AgentVersionRequirement string                     `json:"agentVersionRequirement" yaml:"agentVersionRequirement"`
	IsTriggerAlert          bool                       `json:"isTriggerAlert" yaml:"isTriggerAlert"`
	MitreTactic             string                     `json:"mitreTactic" yaml:"mitreTactic"`
	MitreTechnique          string                     `json:"mitreTechnique" yaml:"mitreTechnique"`
}

type RuleExpressions struct {
	Message        string           `json:"message" yaml:"message"`
	UniqueID       string           `json:"uniqueId" yaml:"uniqueId"`
	RuleExpression []RuleExpression `json:"ruleExpression" yaml:"ruleExpression"`
}

type RuleExpression struct {
	EventType  utils.EventType `json:"eventType" yaml:"eventType"`
	Expression string          `json:"expression" yaml:"expression"`
}
