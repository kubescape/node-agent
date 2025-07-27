package profilevalidator

import (
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/utils"
)

type ProfileValidatorFactoryImpl struct {
	profileValidatorMap maps.SafeMap[utils.EventType, ProfileValidator]
	rulePolicyValidator RulePolicyValidator
}

func NewProfileValidatorFactory(objectCache objectcache.ObjectCache) ProfileValidatorFactory {
	return &ProfileValidatorFactoryImpl{}
}

func (f *ProfileValidatorFactoryImpl) GetProfileValidator(eventType utils.EventType) ProfileValidator {
	return f.profileValidatorMap.Get(eventType)
}

func (f *ProfileValidatorFactoryImpl) RegisterProfileValidator(validator ProfileValidator, eventType utils.EventType) {
	f.profileValidatorMap.Set(eventType, validator)
}

func (f *ProfileValidatorFactoryImpl) UnregisterProfileValidator(eventType utils.EventType) {
	f.profileValidatorMap.Delete(eventType)
}

func (f *ProfileValidatorFactoryImpl) GetRulePolicyValidator() RulePolicyValidator {
	return f.rulePolicyValidator
}
