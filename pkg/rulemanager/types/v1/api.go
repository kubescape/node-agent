package types

import (
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	// RuleVersion is the version of Rule
	RuleVersion string = "v1"
)

var RuleGvr = schema.GroupVersionResource{
	Group:    types.RuleGroup,
	Version:  RuleVersion,
	Resource: types.RulePlural,
}
