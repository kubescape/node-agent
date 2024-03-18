package types

import (
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type RuntimeAlertRuleBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	// Items is the list of RuntimeAlertRuleBinding
	Items []RuntimeAlertRuleBinding `json:"items"`
}

type RuntimeAlertRuleBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Specification of the desired behavior of the RuntimeAlertRuleBinding
	Spec RuntimeAlertRuleBindingSpec `json:"spec,omitempty"`
}

type RuntimeAlertRuleBindingSpec struct {
	Rules             []RuntimeAlertRuleBindingRule `json:"rules" yaml:"rules"`
	PodSelector       metav1.LabelSelector          `json:"podSelector" yaml:"podSelector"`
	NamespaceSelector metav1.LabelSelector          `json:"namespaceSelector" yaml:"namespaceSelector"`
}

type RuntimeAlertRuleBindingRule struct {
	RuleName   string                 `json:"ruleName" yaml:"ruleName"`
	RuleID     string                 `json:"ruleID" yaml:"ruleID"`
	RuleTags   []string               `json:"ruleTags" yaml:"ruleTags"`
	Severity   string                 `json:"severity" yaml:"severity"`
	Parameters map[string]interface{} `json:"parameters" yaml:"parameters"`
}

func (r *RuntimeAlertRuleBindingRule) Equal(other *RuntimeAlertRuleBindingRule) bool {
	if r.RuleName != other.RuleName {
		return false
	}
	if r.RuleID != other.RuleID {
		return false
	}
	if !reflect.DeepEqual(r.RuleTags, other.RuleTags) {
		return false
	}
	if r.Severity != other.Severity {
		return false
	}
	if !reflect.DeepEqual(r.Parameters, other.Parameters) {
		return false
	}
	return true
}
