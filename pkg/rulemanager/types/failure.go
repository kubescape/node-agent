package types

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/utils-k8s-go/wlid"
	"github.com/kubescape/node-agent/pkg/contextdetection"
	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	ApplicationProfile = "applicationprofile"
	NetworkProfile     = "networkprofile"
)

type GenericRuleFailure struct {
	BaseRuntimeAlert       apitypes.BaseRuntimeAlert
	AlertType              apitypes.AlertType
	AlertPlatform          apitypes.AlertSourcePlatform
	RuntimeProcessDetails  apitypes.ProcessTree
	TriggerEvent           utils.EnrichEvent
	RuleAlert              apitypes.RuleAlert
	RuntimeAlertK8sDetails apitypes.RuntimeAlertK8sDetails
	RuntimeAlertECSDetails apitypes.RuntimeAlertECSDetails
	RuleID                 string
	CloudServices          []string
	HttpRuleAlert          apitypes.HttpRuleAlert
	Extra                  interface{}
	IsTriggerAlert         bool
	SourceContext          contextdetection.EventSourceContext
}

type RuleFailure interface {
	// Get Base Runtime Alert
	GetBaseRuntimeAlert() apitypes.BaseRuntimeAlert
	// Get Alert Type
	GetAlertType() apitypes.AlertType
	// Get Runtime Process Details
	GetRuntimeProcessDetails() apitypes.ProcessTree
	// Get Trigger Event
	GetTriggerEvent() utils.EnrichEvent
	// Get Rule Description
	GetRuleAlert() apitypes.RuleAlert
	// Get K8s Runtime Details
	GetRuntimeAlertK8sDetails() apitypes.RuntimeAlertK8sDetails
	// Get ECS Runtime Details
	GetRuntimeAlertEcsDetails() apitypes.RuntimeAlertECSDetails
	// Get Rule ID
	GetRuleId() string
	// Get Cloud Services
	GetCloudServices() []string
	// Get Http Details
	GetHttpRuleAlert() apitypes.HttpRuleAlert
	// Get Alert Platform
	GetAlertPlatform() apitypes.AlertSourcePlatform
	// Get Extra
	GetExtra() interface{}
	// Get Source Context
	GetSourceContext() contextdetection.EventSourceContext

	// Set Workload Details
	SetWorkloadDetails(workloadDetails string)
	// Set Base Runtime Alert
	SetBaseRuntimeAlert(baseRuntimeAlert apitypes.BaseRuntimeAlert)
	// Set Runtime Process Details
	SetRuntimeProcessDetails(runtimeProcessDetails apitypes.ProcessTree)
	// Set Trigger Event
	SetTriggerEvent(triggerEvent utils.EnrichEvent)
	// Set Rule Description
	SetRuleAlert(ruleAlert apitypes.RuleAlert)
	// Set K8s Runtime Details
	SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails apitypes.RuntimeAlertK8sDetails)
	// Set ECS Runtime Details
	SetRuntimeAlertEcsDetails(runtimeAlertEcsDetails apitypes.RuntimeAlertECSDetails)
	// Set Cloud Services
	SetCloudServices(cloudServices []string)
	// Set Alert Platform
	SetAlertPlatform(alertPlatform apitypes.AlertSourcePlatform)
	// Set Http Rule Alert
	SetHttpRuleAlert(httpRuleAlert apitypes.HttpRuleAlert)
	// Set Extra
	SetExtra(extra interface{})
	// Get IsTriggerAlert
	GetIsTriggerAlert() bool
	// Set IsTriggerAlert
	SetIsTriggerAlert(isTriggerAlert bool)
	// Set Source Context
	SetSourceContext(sourceContext contextdetection.EventSourceContext)
}

func (rule *GenericRuleFailure) GetBaseRuntimeAlert() apitypes.BaseRuntimeAlert {
	return rule.BaseRuntimeAlert
}

func (rule *GenericRuleFailure) GetRuntimeProcessDetails() apitypes.ProcessTree {
	return rule.RuntimeProcessDetails
}

func (rule *GenericRuleFailure) GetTriggerEvent() utils.EnrichEvent {
	return rule.TriggerEvent
}

func (rule *GenericRuleFailure) GetRuleAlert() apitypes.RuleAlert {
	return rule.RuleAlert
}

func (rule *GenericRuleFailure) GetRuntimeAlertK8sDetails() apitypes.RuntimeAlertK8sDetails {
	return rule.RuntimeAlertK8sDetails
}

func (rule *GenericRuleFailure) GetRuntimeAlertEcsDetails() apitypes.RuntimeAlertECSDetails {
	return rule.RuntimeAlertECSDetails
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

func (rule *GenericRuleFailure) SetTriggerEvent(triggerEvent utils.EnrichEvent) {
	rule.TriggerEvent = triggerEvent
}

func (rule *GenericRuleFailure) SetRuleAlert(ruleAlert apitypes.RuleAlert) {
	rule.RuleAlert = ruleAlert
}

func (rule *GenericRuleFailure) SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails apitypes.RuntimeAlertK8sDetails) {
	rule.RuntimeAlertK8sDetails = runtimeAlertK8sDetails
}

func (rule *GenericRuleFailure) SetRuntimeAlertEcsDetails(runtimeAlertEcsDetails apitypes.RuntimeAlertECSDetails) {
	rule.RuntimeAlertECSDetails = runtimeAlertEcsDetails
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

func (rule *GenericRuleFailure) SetHttpRuleAlert(httpRuleAlert apitypes.HttpRuleAlert) {
	rule.AlertType = apitypes.AlertTypeHttpRule
	rule.HttpRuleAlert = httpRuleAlert
}

func (rule *GenericRuleFailure) SetExtra(extra interface{}) {
	rule.Extra = extra
}

func (rule *GenericRuleFailure) GetIsTriggerAlert() bool {
	return rule.IsTriggerAlert
}

func (rule *GenericRuleFailure) SetIsTriggerAlert(isTriggerAlert bool) {
	rule.IsTriggerAlert = isTriggerAlert
}

func (rule *GenericRuleFailure) GetSourceContext() contextdetection.EventSourceContext {
	return rule.SourceContext
}

func (rule *GenericRuleFailure) SetSourceContext(sourceContext contextdetection.EventSourceContext) {
	rule.SourceContext = sourceContext
}
