package ruleengine

import (
	"fmt"
	"strings"
	"slices"

	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
)

const (
	R1013ID   = "R1013"
	R1013Name = "Crypto Mining files access"
)

var R1013CryptoMiningFilesAccessRuleDescriptor = RuleDescriptor{
	ID:          R1013ID,
	Name:        R1013Name,
	Description: "Detecting Crypto miners communication by files access",
	Tags:        []string{"crypto", "miners", "malicious", "whitelisted"},
	Priority:    RulePriorityHigh,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.OpenEventType,
		},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1013CryptoMiningFilesAccess()
	},
}
var _ ruleengine.RuleEvaluator = (*R1013CryptoMiningFilesAccess)(nil)

type R1013CryptoMiningFilesAccess struct {
	BaseRule
}

func CreateRuleR1013CryptoMiningFilesAccess() *R1013CryptoMiningFilesAccess {
	return &R1013CryptoMiningFilesAccess{}
}
func (rule *R1013CryptoMiningFilesAccess) Name() string {
	return R1013Name
}

func (rule *R1013CryptoMiningFilesAccess) ID() string {
	return R1013ID
}

func (rule *R1013CryptoMiningFilesAccess) DeleteRule() {
}

func (rule *R1013CryptoMiningFilesAccess) ProcessEvent(eventType utils.EventType, event interface{}, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.OpenEventType {
		return nil
	}

	openEvent, ok := event.(*traceropentype.Event)
	if !ok {
		return nil
	}

	if slices.Contains(utils.CryptoMiningFilesAccessPathsPrefix, openEvent.FullPath) {

	ruleFailure := GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName:      rule.Name(),
			InfectedPID:    openEvent.Pid,
			FixSuggestions: "If this is a legitimate action, please consider removing this workload from the binding of this rule.",
			Severity:       R1013CryptoMiningFilesAccessRuleDescriptor.Priority,
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				Comm: openEvent.Comm,
				Gid:  &openEvent.Gid,
				PID:  openEvent.Pid,
				Uid:  &openEvent.Uid,
			},
			ContainerID: openEvent.Runtime.ContainerID,
		},
		TriggerEvent: openEvent.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: fmt.Sprintf("Unexpected access to crypto mining-related file: %s with flags: %s in: %s", openEvent.FullPath, strings.Join(openEvent.Flags, ","), openEvent.GetContainer()),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName: openEvent.GetPod(),
		},
		RuleID: rule.ID(),
	}

	return &ruleFailure
}
return nil
}

func (rule *R1013CryptoMiningFilesAccess) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1013CryptoMiningFilesAccessRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
