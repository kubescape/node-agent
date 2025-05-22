package ruleprocess

import (
	"errors"
	"fmt"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"
)

func ProcessRule(rule ruleengine.RuleEvaluator, eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	failOnProfile := false
	var finalPayload interface{}
	if rule.Requirements().GetProfileRequirements().ProfileDependency == armotypes.Required ||
		(rule.Requirements().GetProfileRequirements().ProfileDependency == armotypes.Optional) {
		ok, payload, err := rule.EvaluateRuleWithProfile(eventType, event, objCache)
		// if profile is required and there is no profile available, return nil
		// or if profile is required and there is a profile available and no rule failure, continue
		// or if profile is optional and there is no profile available, continue
		// or if profile is optional and there is a profile available and no rule failure, continue
		if !ok && (!errors.Is(err, NoProfileAvailable) ||
			rule.Requirements().GetProfileRequirements().ProfileDependency == armotypes.Required) {
			return nil
		}
		finalPayload = payload
		failOnProfile = ok
	}

	// If profile is not required and there is no rule failure, do basic evaluation
	if !(rule.Requirements().GetProfileRequirements().ProfileDependency == armotypes.Required) && !failOnProfile {
		ok, payload := rule.EvaluateRule(eventType, event, objCache.K8sObjectCache())
		if !ok {
			return nil
		}
		finalPayload = payload
	}

	// Create and return the failure
	ruleFailure := rule.CreateRuleFailure(eventType, event, objCache, finalPayload)
	setProfileMetadata(rule, ruleFailure, objCache, failOnProfile)
	return ruleFailure
}

func setProfileMetadata(rule ruleengine.RuleEvaluator, ruleFailure ruleengine.RuleFailure, objectCache objectcache.ObjectCache, failOnProfile bool) {
	baseRuntimeAlert := ruleFailure.GetBaseRuntimeAlert()
	profileReq := rule.Requirements().GetProfileRequirements()

	switch profileReq.ProfileType {
	case armotypes.ApplicationProfile:
		// TODO: Use get profile metadata
		state := objectCache.ApplicationProfileCache().GetApplicationProfileState(ruleFailure.GetTriggerEvent().Runtime.ContainerID)
		if state != nil {
			profileMetadata := &armotypes.ProfileMetadata{
				Status:            state.Status,
				Completion:        state.Completion,
				Name:              state.Name,
				FailOnProfile:     failOnProfile,
				Type:              armotypes.ApplicationProfile,
				ProfileDependency: profileReq.ProfileDependency,
				Error:             state.Error,
			}
			baseRuntimeAlert.ProfileMetadata = profileMetadata
		}

	case armotypes.NetworkProfile:
		// TODO: Use get profile metadata
		state := objectCache.NetworkNeighborhoodCache().GetNetworkNeighborhoodState(ruleFailure.GetTriggerEvent().Runtime.ContainerID)
		if state != nil {
			profileMetadata := &armotypes.ProfileMetadata{
				Status:            state.Status,
				Completion:        state.Completion,
				Name:              state.Name,
				FailOnProfile:     failOnProfile,
				Type:              armotypes.NetworkProfile,
				ProfileDependency: profileReq.ProfileDependency,
				Error:             state.Error,
			}
			baseRuntimeAlert.ProfileMetadata = profileMetadata
		}
	default:
		profileMetadata := &armotypes.ProfileMetadata{
			ProfileDependency: profileReq.ProfileDependency,
			FailOnProfile:     failOnProfile,
			Error:             fmt.Errorf("profile type %d not supported", profileReq.ProfileType),
		}
		baseRuntimeAlert.ProfileMetadata = profileMetadata
	}
	ruleFailure.SetBaseRuntimeAlert(baseRuntimeAlert)
}
