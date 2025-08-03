package rulemanager

import (
	"slices"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type RulePolicyValidator struct {
	objectCache objectcache.ObjectCache
}

func NewRulePolicyValidator(objectCache objectcache.ObjectCache) *RulePolicyValidator {
	return &RulePolicyValidator{
		objectCache: objectCache,
	}
}

func (v *RulePolicyValidator) Validate(ruleId string, process string, ap *v1beta1.ApplicationProfileContainer) (bool, error) {
	if _, ok := ap.PolicyByRuleId[ruleId]; !ok {
		return false, nil
	}

	if policy, ok := ap.PolicyByRuleId[ruleId]; ok {
		if policy.AllowedContainer || slices.Contains(policy.AllowedProcesses, process) {
			return true, nil
		}
	}

	return false, nil
}
