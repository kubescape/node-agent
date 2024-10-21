package ruleengine

import (
	"github.com/kubescape/node-agent/pkg/ruleengine"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/utils-k8s-go/wlid"
	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

var _ ruleengine.RuleFailure = (*GenericRuleFailure)(nil)

type GenericRuleFailure struct {
	BaseRuntimeAlert       apitypes.BaseRuntimeAlert
	RuntimeProcessDetails  apitypes.ProcessTree
	TriggerEvent           igtypes.Event
	RuleAlert              apitypes.RuleAlert
	RuntimeAlertK8sDetails apitypes.RuntimeAlertK8sDetails
	RuleID                 string
	extra                  interface{}
}

func (rule *GenericRuleFailure) GetBaseRuntimeAlert() apitypes.BaseRuntimeAlert {
	return rule.BaseRuntimeAlert
}

func (rule *GenericRuleFailure) GetRuntimeProcessDetails() apitypes.ProcessTree {
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

func (rule *GenericRuleFailure) GetRuleId() string {
	return rule.RuleID
}

func (rule *GenericRuleFailure) SetBaseRuntimeAlert(baseRuntimeAlert apitypes.BaseRuntimeAlert) {
	rule.BaseRuntimeAlert = baseRuntimeAlert
}

func (rule *GenericRuleFailure) SetRuntimeProcessDetails(runtimeProcessDetails apitypes.ProcessTree) {
	rule.RuntimeProcessDetails = runtimeProcessDetails
}

func (rule *GenericRuleFailure) SetTriggerEvent(triggerEvent igtypes.Event) {
	rule.TriggerEvent = triggerEvent
}

func (rule *GenericRuleFailure) SetRuleAlert(ruleAlert apitypes.RuleAlert) {
	rule.RuleAlert = ruleAlert
}

func (rule *GenericRuleFailure) SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails apitypes.RuntimeAlertK8sDetails) {
	rule.RuntimeAlertK8sDetails = runtimeAlertK8sDetails
}

func (rule *GenericRuleFailure) SetWorkloadDetails(workloadDetails string) {
	if workloadDetails == "" {
		return
	}

	rule.RuntimeAlertK8sDetails.ClusterName = wlid.GetClusterFromWlid(workloadDetails)
	rule.RuntimeAlertK8sDetails.WorkloadKind = wlid.GetKindFromWlid(workloadDetails)
	rule.RuntimeAlertK8sDetails.WorkloadNamespace = wlid.GetNamespaceFromWlid(workloadDetails)
	rule.RuntimeAlertK8sDetails.WorkloadName = wlid.GetNameFromWlid(workloadDetails)
}
