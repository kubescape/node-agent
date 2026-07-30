package types

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/rulemanager/prefilter"
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

// Rule is node-agent's view of a rule from the Rules CRD.
//
// It embeds armotypes.RuntimeRule so the CRD contract -- including StateWrites --
// has exactly one definition, shared with the operator. Two fields are
// deliberately SHADOWED because their types differ from the shared root:
//
//   - Expressions: node-agent's RuleExpression uses utils.EventType, which covers
//     all node-agent event streams and is the type the rule loop compares
//     against. The embedded RuntimeRule.Expressions is unused.
//   - ProfileDataRequired: node-agent's FieldRequirement carries a Declared flag
//     distinguishing "absent" from "present but empty", and rejects unknown keys
//     at unmarshal. armotypes.ProfileDataField has neither.
//
// The two decoders that reach this struct treat the shadows differently.
// encoding/json resolves same-tag conflicts by depth, so only these depth-0
// fields are populated. apimachinery's converter -- the production CRD path --
// has no depth rule and visits every field independently, so it populates the
// embedded copies as well. Either way the depth-0 fields are what all
// node-agent code reads; never read the embedded copies. rule_embedding_test.go
// pins the behaviour of both decoders.
type Rule struct {
	armotypes.RuntimeRule `json:",inline" yaml:",inline"`

	Expressions         RuleExpressions      `json:"expressions" yaml:"expressions"`
	ProfileDataRequired *ProfileDataRequired `json:"profileDataRequired,omitempty" yaml:"profileDataRequired,omitempty"`

	Prefilter *prefilter.Params `json:"-" yaml:"-"`
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
