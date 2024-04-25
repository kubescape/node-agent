package ruleengine

import (
	"fmt"
	"node-agent/pkg/objectcache"
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/utils"
	"slices"
	"strings"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

const (
	R0005ID   = "R0005"
	R0005Name = "Unexpected domain request"
)

var R0005UnexpectedDomainRequestRuleDescriptor = RuleDescriptor{
	ID:          R0005ID,
	Name:        R0005Name,
	Description: "Detecting unexpected domain requests that are not whitelisted by application profile.",
	Tags:        []string{"dns", "whitelisted"},
	Priority:    RulePriorityMed,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{utils.DnsEventType},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR0005UnexpectedDomainRequest()
	},
}
var _ ruleengine.RuleEvaluator = (*R0005UnexpectedDomainRequest)(nil)

type R0005UnexpectedDomainRequest struct {
	BaseRule
}

func CreateRuleR0005UnexpectedDomainRequest() *R0005UnexpectedDomainRequest {
	return &R0005UnexpectedDomainRequest{}
}

func (rule *R0005UnexpectedDomainRequest) Name() string {
	return R0005Name
}
func (rule *R0005UnexpectedDomainRequest) ID() string {
	return R0005ID
}

func (rule *R0005UnexpectedDomainRequest) DeleteRule() {
}

func (rule *R0005UnexpectedDomainRequest) generatePatchCommand(event *tracerdnstype.Event, nn *v1beta1.NetworkNeighborhood) string {
	baseTemplate := "kubectl patch networkneighborhood %s --namespace %s --type merge -p '{\"spec\": {\"containers\": [{\"name\": \"%s\", \"dns\": [{\"dnsName\": \"%s\"}]}]}}'"
	return fmt.Sprintf(baseTemplate, nn.GetName(), nn.GetNamespace(),
		event.GetContainer(), event.DNSName)
}

func (rule *R0005UnexpectedDomainRequest) ProcessEvent(eventType utils.EventType, event interface{}, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.DnsEventType {
		return nil
	}

	domainEvent, ok := event.(*tracerdnstype.Event)
	if !ok {
		return nil
	}

	// TODO: fix this, currently we are ignoring in-cluster communication
	if strings.HasSuffix(domainEvent.DNSName, "svc.cluster.local.") {
		return nil
	}

	nn := objCache.NetworkNeighborhoodCache().GetNetworkNeighborhood(domainEvent.Runtime.ContainerID)
	if nn == nil {
		return nil
	}

	nnContainer, err := getContainerFromNetworkNeighborhood(nn, domainEvent.GetContainer())
	if err != nil {
		return nil
	}

	// Check that the domain is in the network neighbors
	for _, dns := range nnContainer.Egress {
		if dns.DNS == domainEvent.DNSName || slices.Contains(dns.DNSNames, domainEvent.DNSName) {
			return nil
		}
	}

	ruleFailure := GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName:   rule.Name(),
			InfectedPID: domainEvent.Pid,
			FixSuggestions: fmt.Sprintf("If this is a valid behavior, please add the domain %s to the whitelist in the application profile for the Pod %s. You can use the following command: %s",
				domainEvent.DNSName,
				domainEvent.GetPod(),
				rule.generatePatchCommand(domainEvent, nn)),
			Severity: R0005UnexpectedDomainRequestRuleDescriptor.Priority,
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				Comm: domainEvent.Comm,
				Gid:  &domainEvent.Gid,
				PID:  domainEvent.Pid,
				Uid:  &domainEvent.Uid,
			},
			ContainerID: domainEvent.Runtime.ContainerID,
		},
		TriggerEvent: domainEvent.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleID:          rule.ID(),
			RuleDescription: fmt.Sprintf("Unexpected domain communication: %s from: %s", domainEvent.DNSName, domainEvent.GetContainer()),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName: domainEvent.GetPod(),
		},
	}

	return &ruleFailure
}

func (rule *R0005UnexpectedDomainRequest) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R0005UnexpectedDomainRequestRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
