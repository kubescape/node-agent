package ruleengine

import (
	"node-agent/pkg/ruleengine"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/utils-k8s-go/wlid"
	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

var _ ruleengine.RuleFailure = (*GenericRuleFailure)(nil)

type GenericRuleFailure struct {
	Unique                 string // alert identification for deduplication, should be unique per alert (I did not use "ID" so it wont be confused with ruleID)
	BaseRuntimeAlert       apitypes.BaseRuntimeAlert
	RuntimeProcessDetails  apitypes.RuntimeAlertProcessDetails
	TriggerEvent           igtypes.Event
	RuleAlert              apitypes.RuleAlert
	RuntimeAlertK8sDetails apitypes.RuntimeAlertK8sDetails
}

// GetUnique returns the unique identifier of the alert
func (rule *GenericRuleFailure) GetUnique() string {
	return rule.Unique
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

func (rule *GenericRuleFailure) SetWorkloadDetails(workloadDetails string) {
	if workloadDetails == "" {
		return
	}

	cluster := wlid.GetClusterFromWlid(workloadDetails)

	rule.RuntimeAlertK8sDetails.ClusterName = &cluster
	rule.RuntimeAlertK8sDetails.WorkloadKind = wlid.GetKindFromWlid(workloadDetails)
	rule.RuntimeAlertK8sDetails.WorkloadNamespace = wlid.GetNamespaceFromWlid(workloadDetails)
	rule.RuntimeAlertK8sDetails.WorkloadName = wlid.GetNameFromWlid(workloadDetails)
}
