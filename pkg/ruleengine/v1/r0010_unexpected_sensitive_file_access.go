package ruleengine

import (
	"fmt"

	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/rulemanager/v1/ruleprocess"
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

func (rule *R0010UnexpectedSensitiveFileAccess) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache) (bool, interface{}) {
	if eventType != utils.OpenEventType {
		return false, nil
	}

	fullEvent, ok := event.(*events.OpenEvent)
	if !ok {
		return false, nil
	}

	openEvent := fullEvent.Event

	if !utils.IsSensitivePath(openEvent.FullPath, rule.additionalPaths) {
		return false, nil
	}

	// Running without application profile, to avoid false positives check if the process name is legitimate
	for _, processName := range legitimateProcessNames {
		if processName == openEvent.Comm {
			return false, nil
		}
	}

	return true, fullEvent
}

func (rule *R0010UnexpectedSensitiveFileAccess) EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (bool, interface{}, error) {
	// First do basic evaluation
	ok, openEvent := rule.EvaluateRule(eventType, event, objCache.K8sObjectCache())
	if !ok {
		return false, nil, nil
	}

	openEventTyped, _ := openEvent.(*events.OpenEvent)
	ap := objCache.ApplicationProfileCache().GetApplicationProfile(openEventTyped.Runtime.ContainerID)
	if ap == nil {
		return false, nil, ruleprocess.NoProfileAvailable
	}

	appProfileOpenList, err := GetContainerFromApplicationProfile(ap, openEventTyped.GetContainer())
	if err != nil {
		return false, nil, err
	}

	for _, open := range appProfileOpenList.Opens {
		if dynamicpathdetector.CompareDynamic(open.Path, openEventTyped.FullPath) {
			return false, nil, nil
		}
	}

	return true, nil, nil
}

func (rule *R0010UnexpectedSensitiveFileAccess) CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache, payload interface{}) ruleengine.RuleFailure {
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
