package types

import (
	"node-agent/pkg/rulebindingmanager/types"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (

	// RuleBinderVersion is the version of RuleBinder
	// TODO: we should probably set to v1alpha1
	RuleBinderVersion string = "v1"
)

var RuleBindingAlertGvr = schema.GroupVersionResource{
	Group:    types.RuleBinderGroup,
	Version:  RuleBinderVersion,
	Resource: types.RuntimeRuleBindingAlertPlural,
}
