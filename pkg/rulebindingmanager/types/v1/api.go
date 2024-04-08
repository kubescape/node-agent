package types

import (
	"github.com/kubescape/node-agent/pkg/rulebindingmanager/types"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (

	// ApplicationProfileVersion is the version of ApplicationProfile
	// TODO: we should prbably set to v1alpha1
	RuleBinderVersion string = "v1"

	// ApplicationProfileApiVersion is the api version of ApplicationProfile
	RuleBinderApiVersion string = types.RuleBinderGroup + "/" + RuleBinderVersion
)

var RuleBindingAlertGvr schema.GroupVersionResource = schema.GroupVersionResource{
	Group:    types.RuleBinderGroup,
	Version:  RuleBinderVersion,
	Resource: types.RuntimeRuleBindingAlertPlural,
}
