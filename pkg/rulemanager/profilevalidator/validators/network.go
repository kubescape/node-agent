package validators

import (
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilevalidator"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type NetworkProfileValidator struct {
}

func NewNetworkProfileValidator(objectCache objectcache.ObjectCache) profilevalidator.ProfileValidator {
	return &NetworkProfileValidator{}
}

func (v *NetworkProfileValidator) ValidateProfile(event utils.K8sEvent, ap *v1beta1.ApplicationProfileContainer, nn *v1beta1.NetworkNeighborhoodContainer) (bool, error) {
	networkEvent, ok := event.(*tracernetworktype.Event)
	if !ok {
		return false, ErrConversionFailed
	}

	// Check if the network event is in the network neighborhood profile
	for _, egress := range nn.Egress {
		if egress.IPAddress == networkEvent.DstEndpoint.Addr {
			return true, nil
		}
	}

	return false, nil
}
