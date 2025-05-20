package ruleprocess

import (
	"errors"

	"github.com/armosec/armoapi-go/armotypes"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
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
	failOnProfile := false
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

		failOnProfile = ok
	}

	// If profile is not required and there is no rule failure, do basic evaluation
	if !(rule.Requirements().GetProfileRequirements().ProfileDependency == armotypes.Required) && !failOnProfile {
		ok, _ := rule.EvaluateRule(eventType, event, objCache.K8sObjectCache())
		if !ok {
			return nil
		}
	}

	// Create and return the failure
	ruleFailure := rule.CreateRuleFailure(eventType, event, objCache)
	setProfileMetadata(rule, ruleFailure, objCache, failOnProfile)
	return ruleFailure
}

func setProfileMetadata(rule ruleengine.RuleEvaluator, ruleFailure ruleengine.RuleFailure, objectCache objectcache.ObjectCache, failOnProfile bool) {
	baseRuntimeAlert := ruleFailure.GetBaseRuntimeAlert()
	profileReq := rule.Requirements().GetProfileRequirements()

	switch profileReq.ProfileType {
	case armotypes.ApplicationProfile:
		ap := objectCache.ApplicationProfileCache().GetApplicationProfile(ruleFailure.GetTriggerEvent().Runtime.ContainerID)
		if ap != nil {
			profileMetadata := &armotypes.ProfileMetadata{
				Status:            ap.GetAnnotations()[helpersv1.StatusMetadataKey],
				Completion:        ap.GetAnnotations()[helpersv1.CompletionMetadataKey],
				Name:              ap.Name,
				FailOnProfile:     failOnProfile,
				Type:              armotypes.ApplicationProfile,
				ProfileDependency: profileReq.ProfileDependency,
			}
			baseRuntimeAlert.ProfileMetadata = profileMetadata
		}

	case armotypes.NetworkProfile:
		nn := objectCache.NetworkNeighborhoodCache().GetNetworkNeighborhood(ruleFailure.GetTriggerEvent().Runtime.ContainerID)
		if nn != nil {
			profileMetadata := &armotypes.ProfileMetadata{
				Status:            nn.GetAnnotations()[helpersv1.StatusMetadataKey],
				Completion:        nn.GetAnnotations()[helpersv1.CompletionMetadataKey],
				Name:              nn.Name,
				FailOnProfile:     failOnProfile,
				Type:              armotypes.NetworkProfile,
				ProfileDependency: profileReq.ProfileDependency,
			}
			baseRuntimeAlert.ProfileMetadata = profileMetadata
		}
	default:
		profileMetadata := &armotypes.ProfileMetadata{
			ProfileDependency: profileReq.ProfileDependency,
			FailOnProfile:     failOnProfile,
		}
		baseRuntimeAlert.ProfileMetadata = profileMetadata
	}
	ruleFailure.SetBaseRuntimeAlert(baseRuntimeAlert)
}
