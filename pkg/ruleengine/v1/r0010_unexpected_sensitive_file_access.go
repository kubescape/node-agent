package ruleengine

import (
	"fmt"
	"node-agent/pkg/objectcache"
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/utils"
	"strings"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

const (
	R0010ID   = "R0010"
	R0010Name = "Unexpected Sensitive File Access"
)

var R0010UnexpectedSensitiveFileAccessRuleDescriptor = RuleDescriptor{
	ID:          R0010ID,
	Name:        R0010Name,
	Description: "Detecting access to sensitive files.",
	Tags:        []string{"files", "malicious", "whitelisted"},
	Priority:    RulePriorityMed,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.OpenEventType,
		},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR0010UnexpectedSensitiveFileAccess()
	},
}
var _ ruleengine.RuleEvaluator = (*R0010UnexpectedSensitiveFileAccess)(nil)

type R0010UnexpectedSensitiveFileAccess struct {
	BaseRule
	additionalPaths []string
}

func CreateRuleR0010UnexpectedSensitiveFileAccess() *R0010UnexpectedSensitiveFileAccess {
	return &R0010UnexpectedSensitiveFileAccess{
		additionalPaths: SensitiveFiles,
	}
}

func (rule *R0010UnexpectedSensitiveFileAccess) SetParameters(parameters map[string]interface{}) {
	rule.BaseRule.SetParameters(parameters)

	additionalPathsInterface := rule.GetParameters()["additionalPaths"]
	if additionalPathsInterface == nil {
		return
	}

	additionalPaths, ok := interfaceToStringSlice(additionalPathsInterface)
	if ok {
		for _, path := range additionalPaths {
			rule.additionalPaths = append(rule.additionalPaths, fmt.Sprintf("%v", path))
		}
	} else {
		logger.L().Warning("failed to convert additionalPaths to []string", helpers.String("ruleID", rule.ID()))
	}
}

func (rule *R0010UnexpectedSensitiveFileAccess) Name() string {
	return R0010Name
}

func (rule *R0010UnexpectedSensitiveFileAccess) ID() string {
	return R0010ID
}

func (rule *R0010UnexpectedSensitiveFileAccess) DeleteRule() {
}

func (rule *R0010UnexpectedSensitiveFileAccess) ProcessEvent(eventType utils.EventType, event interface{}, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.OpenEventType {
		return nil
	}

	openEvent, ok := event.(*traceropentype.Event)
	if !ok {
		return nil
	}

	ap := objCache.ApplicationProfileCache().GetApplicationProfile(openEvent.Runtime.ContainerID)
	if ap == nil {
		return nil
	}

	appProfileOpenList, err := getContainerFromApplicationProfile(ap, openEvent.GetContainer())
	if err != nil {
		return nil
	}

	isSensitive := false
	for _, path := range rule.additionalPaths {
		if strings.HasPrefix(openEvent.FullPath, path) {
			isSensitive = true
			break
		}
	}

	if !isSensitive {
		return nil
	}

	for _, open := range appProfileOpenList.Opens {
		if open.Path == openEvent.FullPath {
			return nil
		}
	}

	ruleFailure := GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName:      rule.Name(),
			InfectedPID:    openEvent.Pid,
			FixSuggestions: "If this is a legitimate action, please consider removing this workload from the binding of this rule.",
			Severity:       R0010UnexpectedSensitiveFileAccessRuleDescriptor.Priority,
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
			RuleDescription: fmt.Sprintf("Unexpected sensitive file access: %s in: %s", openEvent.FullPath, openEvent.GetContainer()),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName: openEvent.GetPod(),
		},
		RuleID: rule.ID(),
	}

	return &ruleFailure
}

func (rule *R0010UnexpectedSensitiveFileAccess) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R0010UnexpectedSensitiveFileAccessRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
