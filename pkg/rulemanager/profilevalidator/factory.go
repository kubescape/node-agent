package profilevalidator

import (
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/utils"
)

type ProfileValidatorFactoryImpl struct {
	profileValidatorMap maps.SafeMap[utils.EventType, ProfileValidator]
}

func NewProfileValidatorFactory() ProfileValidatorFactory {
	return &ProfileValidatorFactoryImpl{}
}

func (f *ProfileValidatorFactoryImpl) GetProfileValidator(eventType utils.EventType) (ProfileValidator, error) {
	return f.profileValidatorMap.Get(eventType), nil
}

func (f *ProfileValidatorFactoryImpl) RegisterProfileValidator(validator ProfileValidator, eventType utils.EventType) {
	f.profileValidatorMap.Set(eventType, validator)
}

func (f *ProfileValidatorFactoryImpl) UnregisterProfileValidator(eventType utils.EventType) {
	f.profileValidatorMap.Delete(eventType)
}
