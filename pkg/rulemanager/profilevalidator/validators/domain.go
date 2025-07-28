package validators

import (
	"slices"

	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilevalidator"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type DomainProfileValidator struct {
	RequiredEventType utils.EventType
}

func NewDomainProfileValidator(objectCache objectcache.ObjectCache) profilevalidator.ProfileValidator {
	return &DomainProfileValidator{
		RequiredEventType: utils.DnsEventType,
	}
}

func (v *DomainProfileValidator) ValidateProfile(event utils.K8sEvent, ap *v1beta1.ApplicationProfileContainer, nn *v1beta1.NetworkNeighborhoodContainer) (profilevalidator.ProfileValidationResult, error) {
	checks := profilevalidator.ProfileValidationResult{
		Checks: []profilevalidator.ProfileValidationCheck{
			{
				Name:   "domain",
				Result: false,
			},
		},
	}
	dnsEvent, ok := event.(*tracerdnstype.Event)
	if !ok {
		return checks, ErrConversionFailed
	}

	// Check if the domain is in the network neighborhood profile
	for _, egress := range nn.Egress {
		if egress.DNS == dnsEvent.DNSName || slices.Contains(egress.DNSNames, dnsEvent.DNSName) {
			checks.GetCheck("domain").Result = true
		}
	}

	return checks, nil
}

func (v *DomainProfileValidator) GetRequiredEventType() utils.EventType {
	return v.RequiredEventType
}
