package validators

import (
	"slices"

	tracercapabilitiestype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilevalidator"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type CapabilityProfileValidator struct {
	RequiredEventType utils.EventType
}

func NewCapabilityProfileValidator(objectCache objectcache.ObjectCache) profilevalidator.ProfileValidator {
	return &CapabilityProfileValidator{
		RequiredEventType: utils.CapabilitiesEventType,
	}
}

func (v *CapabilityProfileValidator) ValidateProfile(event utils.K8sEvent, ap *v1beta1.ApplicationProfileContainer, nn *v1beta1.NetworkNeighborhoodContainer) (profilevalidator.ProfileValidationResult, error) {
	checks := profilevalidator.ProfileValidationResult{
		Checks: []profilevalidator.ProfileValidationCheck{
			{
				Name:   "capability",
				Result: false,
			},
		},
	}

	capEvent, ok := event.(*tracercapabilitiestype.Event)
	if !ok {
		return checks, ErrConversionFailed
	}

	if slices.Contains(ap.Capabilities, capEvent.CapName) {
		checks.GetCheck("capability").Result = true
	}

	return checks, nil
}

func (v *CapabilityProfileValidator) GetRequiredEventType() utils.EventType {
	return v.RequiredEventType
}
