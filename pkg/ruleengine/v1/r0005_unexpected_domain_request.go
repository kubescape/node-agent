package ruleengine

import (
	"fmt"
	"slices"
	"strings"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
	"github.com/goradd/maps"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	R0005ID   = "R0005"
	R0005Name = "Unexpected domain request"
)

var R0005UnexpectedDomainRequestRuleDescriptor = ruleengine.RuleDescriptor{
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
	alertedDomains maps.SafeMap[string, bool]
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

func (rule *R0005UnexpectedDomainRequest) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache) ruleengine.DetectionResult {
	if eventType != utils.DnsEventType {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	domainEvent, ok := event.(*tracerdnstype.Event)
	if !ok {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	if rule.alertedDomains.Has(domainEvent.DNSName) {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	// TODO: fix this, currently we are ignoring in-cluster communication
	if strings.HasSuffix(domainEvent.DNSName, "svc.cluster.local.") {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	return ruleengine.DetectionResult{IsFailure: true, Payload: domainEvent}
}

func (rule *R0005UnexpectedDomainRequest) EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (ruleengine.DetectionResult, error) {
	// First do basic evaluation
	detectionResult := rule.EvaluateRule(eventType, event, objCache.K8sObjectCache())
	if !detectionResult.IsFailure {
		return detectionResult, nil
	}

	domainEventTyped, _ := event.(*tracerdnstype.Event)
	nn, err := GetNetworkNeighborhood(domainEventTyped.Runtime.ContainerID, objCache)
	if err != nil {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, err
	}

	nnContainer, err := GetContainerFromNetworkNeighborhood(nn, domainEventTyped.GetContainer())
	if err != nil {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, err
	}

	// Check that the domain is in the network neighbors
	for _, dns := range nnContainer.Egress {
		if dns.DNS == domainEventTyped.DNSName || slices.Contains(dns.DNSNames, domainEventTyped.DNSName) {
			return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, nil
		}
	}

	return detectionResult, nil
}

func (rule *R0005UnexpectedDomainRequest) CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache, payload ruleengine.DetectionResult) ruleengine.RuleFailure {
	domainEvent, _ := event.(*tracerdnstype.Event)
	rule.alertedDomains.Set(domainEvent.DNSName, true)

	dstIP := ""
	if len(domainEvent.Addresses) > 0 {
		dstIP = domainEvent.Addresses[0]
	}

	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:    HashStringToMD5(fmt.Sprintf("%s%s", domainEvent.Comm, domainEvent.DNSName)),
			AlertName:   rule.Name(),
			InfectedPID: domainEvent.Pid,
			Arguments: map[string]interface{}{
				"domain":    domainEvent.DNSName,
				"addresses": domainEvent.Addresses,
				"protocol":  domainEvent.Protocol,
				"port":      domainEvent.DstPort,
			},
			Severity: R0005UnexpectedDomainRequestRuleDescriptor.Priority,
			Identifiers: &common.Identifiers{
				Process: &common.ProcessEntity{
					Name: domainEvent.Comm,
				},
				Dns: &common.DnsEntity{
					Domain: domainEvent.DNSName,
				},
				Network: &common.NetworkEntity{
					DstIP:    dstIP,
					Protocol: domainEvent.Protocol,
				},
			},
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				Comm:  domainEvent.Comm,
				Gid:   &domainEvent.Gid,
				PID:   domainEvent.Pid,
				Uid:   &domainEvent.Uid,
				Pcomm: domainEvent.Pcomm,
				Path:  domainEvent.Exepath,
				Cwd:   domainEvent.Cwd,
				PPID:  domainEvent.Ppid,
			},
			ContainerID: domainEvent.Runtime.ContainerID,
		},
		TriggerEvent: domainEvent.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: fmt.Sprintf("Unexpected domain communication: %s from: %s", domainEvent.DNSName, domainEvent.GetContainer()),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:   domainEvent.GetPod(),
			PodLabels: domainEvent.K8s.PodLabels,
		},
		RuleID: rule.ID(),
	}
}

func (rule *R0005UnexpectedDomainRequest) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R0005UnexpectedDomainRequestRuleDescriptor.Requirements.RequiredEventTypes(),
		ProfileRequirements: ruleengine.ProfileRequirement{
			ProfileDependency: apitypes.Required,
			ProfileType:       apitypes.NetworkProfile,
		},
	}
}
