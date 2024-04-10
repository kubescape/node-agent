package ruleengine

import (
	"node-agent/pkg/ruleengine"

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

func (rule *GenericRuleFailure) SetWorkloadDetails(workloadDetails string) {
	if workloadDetails == "" {
		return
	}

	rule.RuntimeAlertK8sDetails.ClusterName = wlid.GetClusterFromWlid(workloadDetails)
	rule.RuntimeAlertK8sDetails.WorkloadKind = wlid.GetKindFromWlid(workloadDetails)
	rule.RuntimeAlertK8sDetails.WorkloadNamespace = wlid.GetNamespaceFromWlid(workloadDetails)
	rule.RuntimeAlertK8sDetails.WorkloadName = wlid.GetNameFromWlid(workloadDetails)
}

func (rule *GenericRuleFailure) SetProcessDetails(processDetails apitypes.ProcessTree) {
	rule.RuntimeProcessDetails = processDetails
}

func (rule *GenericRuleFailure) SetUniqueID(uniqueID uint32) {
	rule.BaseRuntimeAlert.ProcessTreeUniqueID = uniqueID
}
