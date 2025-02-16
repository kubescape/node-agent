package ruleengine

import (
	"fmt"

	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

const (
	R0010ID   = "R0010"
	R0010Name = "Unexpected Sensitive File Access"
)

var R0010UnexpectedSensitiveFileAccessRuleDescriptor = ruleengine.RuleDescriptor{
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

	additionalPaths, ok := InterfaceToStringSlice(additionalPathsInterface)
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

func (rule *R0010UnexpectedSensitiveFileAccess) ProcessEvent(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.OpenEventType {
		return nil
	}

	fullEvent, ok := event.(*events.OpenEvent)
	if !ok {
		return nil
	}

	openEvent := fullEvent.Event

	var appProfileOpenList v1beta1.ApplicationProfileContainer
	var err error

	if objCache != nil {
		ap := objCache.ApplicationProfileCache().GetApplicationProfile(openEvent.Runtime.ContainerID)
		if ap == nil {
			return nil
		}

		appProfileOpenList, err = GetContainerFromApplicationProfile(ap, openEvent.GetContainer())
		if err != nil {
			return nil
		}
	}

	if !utils.IsSensitivePath(openEvent.FullPath, rule.additionalPaths) {
		return nil
	}

	if objCache != nil {
		for _, open := range appProfileOpenList.Opens {
			if dynamicpathdetector.CompareDynamic(open.Path, openEvent.FullPath) {
				return nil
			}
		}
	}

	ruleFailure := GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName: rule.Name(),
			Arguments: map[string]interface{}{
				"path":  openEvent.FullPath,
				"flags": openEvent.Flags,
			},
			InfectedPID: openEvent.Pid,
			Severity:    R0010UnexpectedSensitiveFileAccessRuleDescriptor.Priority,
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
			PodName:   openEvent.GetPod(),
			PodLabels: openEvent.K8s.PodLabels,
		},
		RuleID: rule.ID(),
		Extra:  fullEvent.GetExtra(),
	}

	return &ruleFailure
}

func (rule *R0010UnexpectedSensitiveFileAccess) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R0010UnexpectedSensitiveFileAccessRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
