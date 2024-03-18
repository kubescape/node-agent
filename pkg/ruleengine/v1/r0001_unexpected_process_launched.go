package ruleengine

import (
	"fmt"
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/utils"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

const (
	R0001ID                                = "R0001"
	R0001UnexpectedProcessLaunchedRuleName = "Unexpected process launched"
)

var R0001UnexpectedProcessLaunchedRuleDescriptor = RuleDescriptor{
	ID:          R0001ID,
	Name:        R0001UnexpectedProcessLaunchedRuleName,
	Description: "Detecting exec calls that are not whitelisted by application profile",
	Tags:        []string{"exec", "whitelisted"},
	Priority:    RulePriorityCritical,
	Requirements: &RuleRequirements{
		EventTypes:             []utils.EventType{utils.ExecveEventType},
		NeedApplicationProfile: true,
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR0001UnexpectedProcessLaunched()
	},
}
var _ ruleengine.RuleEvaluator = (*R0001UnexpectedProcessLaunched)(nil)

type R0001UnexpectedProcessLaunched struct {
	BaseRule
}

func (rule *R0001UnexpectedProcessLaunched) Name() string {
	return R0001UnexpectedProcessLaunchedRuleName
}

func CreateRuleR0001UnexpectedProcessLaunched() *R0001UnexpectedProcessLaunched {
	return &R0001UnexpectedProcessLaunched{}
}

func (rule *R0001UnexpectedProcessLaunched) generatePatchCommand(event *tracerexectype.Event, ap *v1beta1.ApplicationProfile) string {
	argList := "["
	for _, arg := range event.Args {
		argList += "\"" + arg + "\","
	}
	// remove the last comma
	if len(argList) > 1 {
		argList = argList[:len(argList)-1]
	}
	argList += "]"
	baseTemplate := "kubectl patch applicationprofile %s --namespace %s --type merge -p '{\"spec\": {\"containers\": [{\"name\": \"%s\", \"execs\": [{\"path\": \"%s\", \"args\": %s}]}]}}'"
	return fmt.Sprintf(baseTemplate, ap.GetName(), ap.GetNamespace(),
		event.GetContainer(), getExecPathFromEvent(event), argList)
}

func (rule *R0001UnexpectedProcessLaunched) ProcessEvent(eventType utils.EventType, event interface{}, ap *v1beta1.ApplicationProfile, k8sCache ruleengine.K8sCache) ruleengine.RuleFailure {
	if eventType != utils.ExecveEventType {
		return nil
	}

	execEvent, ok := event.(*tracerexectype.Event)
	if !ok {
		return nil
	}
	p := getExecPathFromEvent(execEvent)

	if ap == nil {
		return &GenericRuleFailure{
			RuleName:         rule.Name(),
			Err:              "Application profile is missing",
			FailureEvent:     utils.ExecToGeneralEvent(execEvent),
			FixSuggestionMsg: fmt.Sprintf("Please create an application profile for the Pod \"%s\" and add the exec call \"%s\" to the whitelist", execEvent.GetPod(), p),
			RulePriority:     R0001UnexpectedProcessLaunchedRuleDescriptor.Priority,
		}
	}

	appProfileExecList, err := getContainerFromApplicationProfile(ap, execEvent.GetContainer())
	if err != nil {
		return &GenericRuleFailure{
			RuleName:         rule.Name(),
			Err:              "Application profile is missing",
			FailureEvent:     utils.ExecToGeneralEvent(execEvent),
			FixSuggestionMsg: fmt.Sprintf("Please create an application profile for the Pod \"%s\" and add the exec call \"%s\" to the whitelist", execEvent.GetPod(), p),
			RulePriority:     R0001UnexpectedProcessLaunchedRuleDescriptor.Priority,
		}
	}

	for _, execCall := range appProfileExecList.Execs {
		if execCall.Path == p {
			return nil
		}
	}

	return &GenericRuleFailure{
		RuleName:         rule.Name(),
		Err:              fmt.Sprintf("exec call \"%s\" is not whitelisted by application profile", p),
		FailureEvent:     utils.ExecToGeneralEvent(execEvent),
		FixSuggestionMsg: fmt.Sprintf("If this is a valid behavior, please add the exec call \"%s\" to the whitelist in the application profile for the Pod \"%s\". You can use the following command: %s", p, execEvent.GetPod(), rule.generatePatchCommand(execEvent, ap)),
		RulePriority:     R0001UnexpectedProcessLaunchedRuleDescriptor.Priority,
	}
}

func (rule *R0001UnexpectedProcessLaunched) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes:             []utils.EventType{utils.ExecveEventType},
		NeedApplicationProfile: true,
	}
}
