package validators

import (
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilevalidator"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type NetworkProfileValidator struct {
	RequiredEventType utils.EventType
	objectCache       objectcache.ObjectCache
}

func NewNetworkProfileValidator(objectCache objectcache.ObjectCache) profilevalidator.ProfileValidator {
	return &NetworkProfileValidator{
		RequiredEventType: utils.NetworkEventType,
		objectCache:       objectCache,
	}
}

func (v *NetworkProfileValidator) ValidateProfile(event utils.K8sEvent, ap *v1beta1.ApplicationProfileContainer, nn *v1beta1.NetworkNeighborhoodContainer) (profilevalidator.ProfileValidationResult, error) {
	checks := profilevalidator.ProfileValidationResult{
		Checks: []profilevalidator.ProfileValidationCheck{
			{
				Name:   "network",
				Result: false,
			},
			{
				Name:   "dns_resolution",
				Result: false,
			},
		},
	}
	networkEvent, ok := event.(*tracernetworktype.Event)
	if !ok {
		return profilevalidator.ProfileValidationResult{}, ErrConversionFailed
	}

	// Check if the network event is in the network neighborhood profile
	for _, egress := range nn.Egress {
		if egress.IPAddress == networkEvent.DstEndpoint.Addr {
			checks.GetCheck("network").Result = true
		}
	}

	domain := v.objectCache.DnsCache().ResolveIpToDomain(networkEvent.DstEndpoint.Addr)
	if domain != "" {
		checks.GetCheck("dns_resolution").Result = true
	}

	return checks, nil
}

func (v *NetworkProfileValidator) GetRequiredEventType() utils.EventType {
	return v.RequiredEventType
}
