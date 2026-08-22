package rulemanager

import (
	"slices"

	"github.com/kubescape/node-agent/pkg/contextdetection"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/rulecreator"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
)

type RulePolicyValidator struct {
	objectCache objectcache.ObjectCache
}

func NewRulePolicyValidator(objectCache objectcache.ObjectCache) *RulePolicyValidator {
	return &RulePolicyValidator{
		objectCache: objectCache,
	}
}

func (v *RulePolicyValidator) Validate(ruleId string, process string, pcp *objectcache.ProjectedContainerProfile) (bool, error) {
	if pcp == nil {
		return false, nil
	}
	policy, ok := pcp.PolicyByRuleId[ruleId]
	if !ok {
		return false, nil
	}
	if policy.AllowedContainer || slices.Contains(policy.AllowedProcesses, process) {
		return true, nil
	}
	return false, nil
}

func RuleAppliesToContext(rule *typesv1.Rule, contextInfo contextdetection.ContextInfo) bool {
	var currentContext contextdetection.EventSourceContext
	if contextInfo == nil {
		currentContext = contextdetection.Kubernetes
	} else {
		currentContext = contextInfo.Context()
	}
	return rulecreator.RuleMatchesContext(rule, currentContext)
}
