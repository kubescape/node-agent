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
	profileDependency := rule.Requirements().GetProfileRequirements().ProfileDependency

	// Handle profile-based evaluation
	if profileDependency == armotypes.Required || profileDependency == armotypes.Optional {
		return processWithProfile(rule, eventType, event, objCache, profileDependency)
	}

	// Handle basic evaluation (no profile dependency)
	return processBasicRule(rule, eventType, event, objCache)
}

func processWithProfile(rule ruleengine.RuleEvaluator, eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache, profileDependency armotypes.ProfileDependency) ruleengine.RuleFailure {
	result, err := rule.EvaluateRuleWithProfile(eventType, event, objCache)

	// Handle profile evaluation results
	switch {
	case errors.Is(err, NoProfileAvailable):
		if profileDependency == armotypes.Required {
			return nil // Required profile not available - no failure
		}
		// Optional profile not available - fall back to basic evaluation
		ruleFailure := processBasicRule(rule, eventType, event, objCache)
		if ruleFailure != nil {
			setProfileMetadata(rule, ruleFailure, objCache, false)
			return ruleFailure
		}
		return nil // No failure from basic evaluation
	case result.IsFailure:
		// Profile evaluation failed - create failure with profile metadata
		return createRuleFailureWithProfile(rule, eventType, event, objCache, result, true)

	default:
		// Profile evaluation passed - no failure
		return nil
	}
}

func processBasicRule(rule ruleengine.RuleEvaluator, eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	result := rule.EvaluateRule(eventType, event, objCache.K8sObjectCache())
	if !result.IsFailure {
		return nil
	}

	ruleFailure := rule.CreateRuleFailure(eventType, event, objCache, result)
	return ruleFailure
}

func createRuleFailureWithProfile(rule ruleengine.RuleEvaluator, eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache, payload ruleengine.DetectionResult, failOnProfile bool) ruleengine.RuleFailure {
	ruleFailure := rule.CreateRuleFailure(eventType, event, objCache, payload)
	if ruleFailure == nil {
		return nil
	}

	setProfileMetadata(rule, ruleFailure, objCache, failOnProfile)
	return ruleFailure
}

func setProfileMetadata(rule ruleengine.RuleEvaluator, ruleFailure ruleengine.RuleFailure, objectCache objectcache.ObjectCache, failOnProfile bool) {
	baseRuntimeAlert := ruleFailure.GetBaseRuntimeAlert()
	profileReq := rule.Requirements().GetProfileRequirements()

	switch profileReq.ProfileType {
	case armotypes.ApplicationProfile:
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
