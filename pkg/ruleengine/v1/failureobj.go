package ruleengine

import (
	"node-agent/pkg/ruleengine"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

var _ ruleengine.RuleFailure = (*GenericRuleFailure)(nil)

type GenericRuleFailure struct {
	BaseRuntimeAlert       apitypes.BaseRuntimeAlert
	RuntimeProcessDetails  apitypes.RuntimeAlertProcessDetails
	TriggerEvent           igtypes.Event
	RuleAlert              apitypes.RuleAlert
	RuntimeAlertK8sDetails apitypes.RuntimeAlertK8sDetails
}

func (rule *GenericRuleFailure) GetBaseRuntimeAlert() apitypes.BaseRuntimeAlert {
	return rule.BaseRuntimeAlert
}

func (rule *GenericRuleFailure) GetRuntimeProcessDetails() apitypes.RuntimeAlertProcessDetails {
	return rule.RuntimeProcessDetails
}

func (rule *GenericRuleFailure) GetTriggerEvent() igtypes.Event {
	return rule.TriggerEvent
}

func (rule *GenericRuleFailure) GetRuleAlert() apitypes.RuleAlert {
	return rule.RuleAlert
}

func (rule *GenericRuleFailure) GetRuntimeAlertK8sDetails() apitypes.RuntimeAlertK8sDetails {
	return rule.RuntimeAlertK8sDetails
}
