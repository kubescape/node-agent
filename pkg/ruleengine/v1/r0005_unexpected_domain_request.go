package ruleengine

import (
	"fmt"
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/utils"

	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

const (
	R0005ID                              = "R0005"
	R0005UnexpectedDomainRequestRuleName = "Unexpected domain request"
)

var R0005UnexpectedDomainRequestRuleDescriptor = RuleDescriptor{
	ID:          R0005ID,
	Name:        R0005UnexpectedDomainRequestRuleName,
	Description: "Detecting unexpected domain requests that are not whitelisted by application profile.",
	Tags:        []string{"dns", "whitelisted"},
	Priority:    RulePriorityMed,
	Requirements: &RuleRequirements{
		EventTypes:             []utils.EventType{utils.DnsEventType},
		NeedApplicationProfile: true,
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
	return R0005UnexpectedDomainRequestRuleName
}
func (rule *R0005UnexpectedDomainRequest) ID() string {
	return R0005ID
}

func (rule *R0005UnexpectedDomainRequest) DeleteRule() {
}

func (rule *R0005UnexpectedDomainRequest) generatePatchCommand(event *tracerdnstype.Event, ap *v1beta1.ApplicationProfile) string {
	baseTemplate := "kubectl patch applicationprofile %s --namespace %s --type merge -p '{\"spec\": {\"containers\": [{\"name\": \"%s\", \"dns\": [{\"dnsName\": \"%s\"}]}]}}'"
	return fmt.Sprintf(baseTemplate, ap.GetName(), ap.GetNamespace(),
		event.GetContainer(), event.DNSName)
}

func (rule *R0005UnexpectedDomainRequest) ProcessEvent(eventType utils.EventType, event interface{}, ap *v1beta1.ApplicationProfile, k8sProvider ruleengine.K8sObjectProvider) ruleengine.RuleFailure {
	// FIXME: Add DNS resolution to the application profile, other option: get the network neighbor
	// Currently this rule is not supported
	return nil

	if eventType != utils.DnsEventType {
		return nil
	}

	domainEvent, ok := event.(*tracerdnstype.Event)
	if !ok {
		return nil
	}

	if ap == nil {
		return &GenericRuleFailure{
			RuleName:         rule.Name(),
			RuleID:           rule.ID(),
			Err:              "Application profile is missing",
			FixSuggestionMsg: fmt.Sprintf("Create an application profile with the domain %s", domainEvent.DNSName),
			FailureEvent:     utils.DnsToGeneralEvent(domainEvent),
			RulePriority:     R0005UnexpectedDomainRequestRuleDescriptor.Priority,
		}
	}
	_, err := getContainerFromApplicationProfile(ap, domainEvent.GetContainer())
	if err != nil {
		return &GenericRuleFailure{
			RuleName:         rule.Name(),
			RuleID:           rule.ID(),
			Err:              "Application profile is missing",
			FixSuggestionMsg: fmt.Sprintf("Create an application profile with the domain %s", domainEvent.DNSName),
			FailureEvent:     utils.DnsToGeneralEvent(domainEvent),
			RulePriority:     R0005UnexpectedDomainRequestRuleDescriptor.Priority,
		}
	}

	// FIXME: Add DNS resolution to the application profile, other option: get the network neighbor
	// // Check that the domain is in the application profile
	// for _, dns := range appProfileDnsList.DNS {
	// 	if dns == domainEvent.DNSName {
	// 		return nil
	// 	}
	// }

	return &GenericRuleFailure{
		RuleName: rule.Name(),
		RuleID:   rule.ID(),
		Err:      fmt.Sprintf("Unexpected domain request (%s)", domainEvent.DNSName),
		FixSuggestionMsg: fmt.Sprintf("If this is a valid behavior, please add the domain %s to the whitelist in the application profile for the Pod %s. You can use the following command: %s",
			domainEvent.DNSName,
			domainEvent.DNSName,
			rule.generatePatchCommand(domainEvent, ap)),
		FailureEvent: utils.DnsToGeneralEvent(domainEvent),
		RulePriority: R0005UnexpectedDomainRequestRuleDescriptor.Priority,
	}
}

func (rule *R0005UnexpectedDomainRequest) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes:             []utils.EventType{utils.DnsEventType},
		NeedApplicationProfile: true,
	}
}
