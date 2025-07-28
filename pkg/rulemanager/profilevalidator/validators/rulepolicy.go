package validators

import (
	"slices"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilevalidator"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type RulePolicyValidator struct {
	objectCache objectcache.ObjectCache
}

func NewRulePolicyValidator(objectCache objectcache.ObjectCache) profilevalidator.RulePolicyValidator {
	return &RulePolicyValidator{
		objectCache: objectCache,
	}
}

func (v *RulePolicyValidator) ValidateRulePolicy(ruleId string, process string, ap *v1beta1.ApplicationProfileContainer, nn *v1beta1.NetworkNeighborhoodContainer) (profilevalidator.ProfileValidationResult, error) {
	checks := profilevalidator.ProfileValidationResult{
		Checks: []profilevalidator.ProfileValidationCheck{
			{
				Name:   "rule_policy",
				Result: false,
			},
		},
	}

	if _, ok := ap.PolicyByRuleId[ruleId]; !ok {
		return checks, nil
	}

	if policy, ok := ap.PolicyByRuleId[ruleId]; ok {
		if policy.AllowedContainer || slices.Contains(policy.AllowedProcesses, process) {
			checks.GetCheck("rule_policy").Result = true
		}
	}

	return checks, nil
}
