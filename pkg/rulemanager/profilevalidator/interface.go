package profilevalidator

import (
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type ProfileRegistry interface {
	GetAvailableProfiles(containerName, containerID string) (*v1beta1.ApplicationProfileContainer, *v1beta1.NetworkNeighborhoodContainer, bool)
}

type ProfileValidatorFactory interface {
	GetProfileValidator(eventType utils.EventType) ProfileValidator
	RegisterProfileValidator(validator ProfileValidator, eventType utils.EventType)
	UnregisterProfileValidator(eventType utils.EventType)
	GetRulePolicyValidator() RulePolicyValidator
}

type ProfileValidator interface {
	ValidateProfile(event utils.K8sEvent, ap *v1beta1.ApplicationProfileContainer, nn *v1beta1.NetworkNeighborhoodContainer) (ProfileValidationResult, error)
	GetRequiredEventType() utils.EventType
}

type RulePolicyValidator interface {
	ValidateRulePolicy(ruleId string, process string, ap *v1beta1.ApplicationProfileContainer, nn *v1beta1.NetworkNeighborhoodContainer) (ProfileValidationResult, error)
}

type ProfileValidationResult struct {
	Checks []ProfileValidationCheck
}

type EventWithChecks struct {
	Event         utils.K8sEvent  `json:"event"`
	ProfileChecks map[string]bool `json:"profile_checks"`
}

type ProfileValidationCheck struct {
	Name   string `json:"name"`
	Result bool   `json:"result"`
}

func (p *ProfileValidationResult) GetCheck(name string) *ProfileValidationCheck {
	for i, check := range p.Checks {
		if check.Name == name {
			return &p.Checks[i]
		}
	}
	return nil
}

func (p *ProfileValidationResult) GetChecksAsMap() map[string]bool {
	checks := make(map[string]bool)
	for _, check := range p.Checks {
		checks[check.Name] = check.Result
	}
	return checks
}
