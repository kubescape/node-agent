package ruleengine

import (
	"fmt"
	"strings"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"

	tracersymlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/symlink/types"
)

const (
	R1010ID   = "R1010"
	R1010Name = "Symlink Created Over Sensitive File"
)

var R1010SymlinkCreatedOverSensitiveFileRuleDescriptor = ruleengine.RuleDescriptor{
	ID:          R1010ID,
	Name:        R1010Name,
	Description: "Detecting symlink creation over sensitive files.",
	Tags:        []string{"files", "malicious"},
	Priority:    RulePriorityHigh,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.SymlinkEventType,
		},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1010SymlinkCreatedOverSensitiveFile()
	},
	RulePolicySupport: true,
}

var _ ruleengine.RuleEvaluator = (*R1010SymlinkCreatedOverSensitiveFile)(nil)

type R1010SymlinkCreatedOverSensitiveFile struct {
	BaseRule
	additionalPaths []string
}

func CreateRuleR1010SymlinkCreatedOverSensitiveFile() *R1010SymlinkCreatedOverSensitiveFile {
	return &R1010SymlinkCreatedOverSensitiveFile{
		additionalPaths: SensitiveFiles,
	}
}

func (rule *R1010SymlinkCreatedOverSensitiveFile) SetParameters(parameters map[string]interface{}) {
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

func (rule *R1010SymlinkCreatedOverSensitiveFile) Name() string {
	return R1010Name
}

func (rule *R1010SymlinkCreatedOverSensitiveFile) ID() string {
	return R1010ID
}

func (rule *R1010SymlinkCreatedOverSensitiveFile) DeleteRule() {
}

func (rule *R1010SymlinkCreatedOverSensitiveFile) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache) ruleengine.DetectionResult {
	if eventType != utils.SymlinkEventType {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	symlinkEvent, ok := event.(*tracersymlinktype.Event)
	if !ok {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	for _, path := range rule.additionalPaths {
		if strings.HasPrefix(symlinkEvent.OldPath, path) {
			return ruleengine.DetectionResult{IsFailure: true, Payload: symlinkEvent.OldPath}
		}
	}

	return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
}

func (rule *R1010SymlinkCreatedOverSensitiveFile) EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (ruleengine.DetectionResult, error) {
	// First do basic evaluation
	detectionResult := rule.EvaluateRule(eventType, event, objCache.K8sObjectCache())
	if !detectionResult.IsFailure {
		return detectionResult, nil
	}

	symlinkEventTyped, _ := event.(*tracersymlinktype.Event)
	if allowed, err := IsAllowed(&symlinkEventTyped.Event, objCache, symlinkEventTyped.Comm, R1010ID); err != nil {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, err
	} else if allowed {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, nil
	}

	return detectionResult, nil
}

func (rule *R1010SymlinkCreatedOverSensitiveFile) CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache, payload ruleengine.DetectionResult) ruleengine.RuleFailure {
	symlinkEvent, _ := event.(*tracersymlinktype.Event)

	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:  HashStringToMD5(fmt.Sprintf("%s%s", symlinkEvent.Comm, symlinkEvent.OldPath)),
			AlertName: rule.Name(),
			Arguments: map[string]interface{}{
				"oldPath": symlinkEvent.OldPath,
				"newPath": symlinkEvent.NewPath,
			},
			InfectedPID: symlinkEvent.Pid,
			Severity:    R1010SymlinkCreatedOverSensitiveFileRuleDescriptor.Priority,
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				Comm:       symlinkEvent.Comm,
				PPID:       symlinkEvent.PPid,
				PID:        symlinkEvent.Pid,
				UpperLayer: &symlinkEvent.UpperLayer,
				Uid:        &symlinkEvent.Uid,
				Gid:        &symlinkEvent.Gid,
				Hardlink:   symlinkEvent.ExePath,
				Path:       symlinkEvent.ExePath,
			},
			ContainerID: symlinkEvent.Runtime.ContainerID,
		},
		TriggerEvent: symlinkEvent.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: fmt.Sprintf("Symlink created over sensitive file: %s - %s", symlinkEvent.OldPath, symlinkEvent.NewPath),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:   symlinkEvent.GetPod(),
			PodLabels: symlinkEvent.K8s.PodLabels,
		},
		RuleID: rule.ID(),
		Extra:  symlinkEvent.GetExtra(),
	}
}

func (rule *R1010SymlinkCreatedOverSensitiveFile) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1010SymlinkCreatedOverSensitiveFileRuleDescriptor.Requirements.RequiredEventTypes(),
		ProfileRequirements: ruleengine.ProfileRequirement{
			ProfileDependency: apitypes.Optional,
			ProfileType:       apitypes.ApplicationProfile,
		},
	}
}
