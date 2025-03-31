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
	AlertType              apitypes.AlertType
	AlertPlatform          apitypes.AlertSourcePlatform
	RuntimeProcessDetails  apitypes.ProcessTree
	TriggerEvent           igtypes.Event
	RuleAlert              apitypes.RuleAlert
	RuntimeAlertK8sDetails apitypes.RuntimeAlertK8sDetails
	RuleID                 string
	CloudServices          []string
	HttpRuleAlert          apitypes.HttpRuleAlert
	Extra                  interface{}
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

func (rule *GenericRuleFailure) GetExtra() interface{} {
	return rule.Extra
}

func (rule *GenericRuleFailure) GetCloudServices() []string {
	return rule.CloudServices
}

func (rule *GenericRuleFailure) GetHttpRuleAlert() apitypes.HttpRuleAlert {
	return rule.HttpRuleAlert
}

func (rule *GenericRuleFailure) GetAlertType() apitypes.AlertType {
	return rule.AlertType
}

func (rule *GenericRuleFailure) GetAlertPlatform() apitypes.AlertSourcePlatform {
	return rule.AlertPlatform
}

func (rule *GenericRuleFailure) SetCloudServices(cloudServices []string) {
	rule.CloudServices = cloudServices
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

func (rule *GenericRuleFailure) SetAlertPlatform(alertPlatform apitypes.AlertSourcePlatform) {
	rule.AlertPlatform = alertPlatform
}
