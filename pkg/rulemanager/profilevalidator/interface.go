package profilevalidator

import (
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type ProfileRegistry interface {
	GetAvailableProfiles(containerName, containerID string) (*v1beta1.ApplicationProfileContainer, *v1beta1.NetworkNeighborhoodContainer, bool)
}

type ProfileValidatorFactory interface {
	GetProfileValidator(eventType utils.EventType) (ProfileValidator, error)
	RegisterProfileValidator(validator ProfileValidator, eventType utils.EventType)
	UnregisterProfileValidator(eventType utils.EventType)
}

type ProfileValidator interface {
	ValidateProfile(event utils.K8sEvent, ap *v1beta1.ApplicationProfileContainer, nn *v1beta1.NetworkNeighborhoodContainer) (bool, error)
}
