package rulemanager

import (
	"slices"
	"strings"

	"github.com/kubescape/node-agent/pkg/contextdetection"
	"github.com/kubescape/node-agent/pkg/objectcache"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
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

// RuleAppliesToContext checks if a rule should execute in the given context
func RuleAppliesToContext(rule *typesv1.Rule, contextInfo contextdetection.ContextInfo) bool {
	var currentContext contextdetection.EventSourceContext
	if contextInfo == nil {
		currentContext = contextdetection.Kubernetes
	} else {
		currentContext = contextInfo.Context()
	}

	var contextTags []string
	for _, tag := range rule.Tags {
		if strings.HasPrefix(tag, "context:") {
			ctx := strings.TrimPrefix(tag, "context:")
			contextTags = append(contextTags, ctx)
		}
	}

	if len(contextTags) > 0 {
		for _, ctx := range contextTags {
			if ctx == string(currentContext) {
				return true
			}
		}
		return false
	}

	// No context specified in either field or tags: default to kubernetes only (backward compatible)
	return currentContext == contextdetection.Kubernetes
}
