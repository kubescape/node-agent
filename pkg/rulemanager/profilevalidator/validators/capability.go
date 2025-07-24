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
}

func NewCapabilityProfileValidator(objectCache objectcache.ObjectCache) profilevalidator.ProfileValidator {
	return &CapabilityProfileValidator{}
}

func (v *CapabilityProfileValidator) ValidateProfile(event utils.K8sEvent, ap *v1beta1.ApplicationProfileContainer, nn *v1beta1.NetworkNeighborhoodContainer) (bool, error) {
	capEvent, ok := event.(*tracercapabilitiestype.Event)
	if !ok {
		return false, ErrConversionFailed
	}

	if slices.Contains(ap.Capabilities, capEvent.CapName) {
		return true, nil
	}

	return false, nil
}
