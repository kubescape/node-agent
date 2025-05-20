package ruleprocess

import (
	"errors"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"
)

func IsProfileExists(objCache objectcache.ObjectCache, containerID string, profileType armotypes.ProfileType) bool {
	switch profileType {
	case armotypes.ApplicationProfile:
		ap := objCache.ApplicationProfileCache().GetApplicationProfile(containerID)
		return ap != nil

	case armotypes.NetworkProfile:
		nn := objCache.NetworkNeighborhoodCache().GetNetworkNeighborhood(containerID)
		return nn != nil

	default:
		return false
	}
}

func ProcessRule(rule ruleengine.RuleEvaluator, eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	isRuleFailure := false
	if rule.Requirements().GetProfileRequirements().ProfileDependency == armotypes.Required ||
		(rule.Requirements().GetProfileRequirements().ProfileDependency == armotypes.Optional) {
		ok, _, err := rule.EvaluateRuleWithProfile(eventType, event, objCache)
		// if profile is required and there is no profile available, return nil
		// or if profile is optional and there is no profile available, continue
		// or if profile is required and there is a profile available and no rule failure, continue
		if !ok && (!errors.Is(err, NoProfileAvailable) ||
			rule.Requirements().GetProfileRequirements().ProfileDependency == armotypes.Required) {
			return nil
		}

		isRuleFailure = ok
	}

	// If profile is not required and there is no rule failure, do basic evaluation
	if !(rule.Requirements().GetProfileRequirements().ProfileDependency == armotypes.Required) && !isRuleFailure {
		ok, _ := rule.EvaluateRule(eventType, event, objCache.K8sObjectCache())
		if !ok {
			return nil
		}
	}

	// Create and return the failure
	return rule.CreateRuleFailure(eventType, event, objCache)
}
