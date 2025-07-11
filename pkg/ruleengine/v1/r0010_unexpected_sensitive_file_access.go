package ruleengine

import (
	"fmt"
	"path/filepath"

	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
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

var legitimateProcessNames = []string{
	"systemd",
	"sudo",
	"passwd",
	"chpasswd",
	"useradd",
	"usermod",
	"chage",
	"sshd",
	"login",
	"su",
	"groupadd",
	"groupmod",
	"dpkg",
	"rpm",
	"ansible",
	"puppet-agent",
	"chef-client",
	"vipw",
	"pwck",
	"grpck",
	"nscd",
	"cron",
	"crond",
	"pam",
	"snap",
	"apk",
	"yum",
	"dnf",
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

func (rule *R0010UnexpectedSensitiveFileAccess) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache) ruleengine.DetectionResult {
	if eventType != utils.OpenEventType {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	fullEvent, ok := event.(*events.OpenEvent)
	if !ok {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	openEvent := fullEvent.Event

	if !utils.IsSensitivePath(openEvent.FullPath, rule.additionalPaths) {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	// Running without application profile, to avoid false positives check if the process name is legitimate
	for _, processName := range legitimateProcessNames {
		if processName == openEvent.Comm {
			return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
		}
	}

	return ruleengine.DetectionResult{IsFailure: true, Payload: openEvent.Comm}
}

func (rule *R0010UnexpectedSensitiveFileAccess) EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (ruleengine.DetectionResult, error) {
	// First do basic evaluation
	detectionResult := rule.EvaluateRule(eventType, event, objCache.K8sObjectCache())
	if !detectionResult.IsFailure {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, nil
	}

	openEventTyped, _ := event.(*events.OpenEvent)
	ap, err := GetApplicationProfile(openEventTyped.Runtime.ContainerID, objCache)
	if err != nil {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, err
	}

	appProfileOpenList, err := GetContainerFromApplicationProfile(ap, openEventTyped.GetContainer())
	if err != nil {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, err
	}

	for _, open := range appProfileOpenList.Opens {
		if dynamicpathdetector.CompareDynamic(open.Path, openEventTyped.FullPath) {
			return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, nil
		}
	}

	return detectionResult, nil
}

func (rule *R0010UnexpectedSensitiveFileAccess) CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache, payload ruleengine.DetectionResult) ruleengine.RuleFailure {
	fullEvent, _ := event.(*events.OpenEvent)
	openEvent := fullEvent.Event

	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:  HashStringToMD5(fmt.Sprintf("%s%s", openEvent.Comm, openEvent.FullPath)),
			AlertName: rule.Name(),
			Arguments: map[string]interface{}{
				"path":  openEvent.FullPath,
				"flags": openEvent.Flags,
			},
			InfectedPID: openEvent.Pid,
			Severity:    R0010UnexpectedSensitiveFileAccessRuleDescriptor.Priority,
			Identifiers: &common.Identifiers{
				Process: &common.ProcessEntity{
					Name: openEvent.Comm,
				},
				File: &common.FileEntity{
					Name:      filepath.Base(openEvent.FullPath),
					Directory: filepath.Dir(openEvent.FullPath),
				},
			},
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
			RuleDescription: fmt.Sprintf("Unexpected sensitive file access: %s", openEvent.FullPath),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:   openEvent.GetPod(),
			PodLabels: openEvent.K8s.PodLabels,
		},
		RuleID: rule.ID(),
		Extra:  fullEvent.GetExtra(),
	}
}

func (rule *R0010UnexpectedSensitiveFileAccess) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R0010UnexpectedSensitiveFileAccessRuleDescriptor.Requirements.RequiredEventTypes(),
		ProfileRequirements: ruleengine.ProfileRequirement{
			ProfileDependency: apitypes.Optional,
			ProfileType:       apitypes.ApplicationProfile,
		},
	}
}
