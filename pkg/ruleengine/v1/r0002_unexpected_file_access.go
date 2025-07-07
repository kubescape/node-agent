package ruleengine

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"

	"github.com/kubescape/node-agent/pkg/objectcache"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

const (
	R0002ID   = "R0002"
	R0002Name = "Unexpected file access"
)

var R0002UnexpectedFileAccessRuleDescriptor = ruleengine.RuleDescriptor{
	ID:          R0002ID,
	Name:        R0002Name,
	Description: "Detecting file access that are not whitelisted by application profile. File access is defined by the combination of path and flags",
	Tags:        []string{"open", "whitelisted"},
	Priority:    RulePriorityLow,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{utils.OpenEventType},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR0002UnexpectedFileAccess()
	},
}
var _ ruleengine.RuleEvaluator = (*R0002UnexpectedFileAccess)(nil)

type R0002UnexpectedFileAccess struct {
	BaseRule
	shouldIgnoreMounts bool
	ignorePrefixes     []string
	includePrefixes    []string
}

func CreateRuleR0002UnexpectedFileAccess() *R0002UnexpectedFileAccess {
	return &R0002UnexpectedFileAccess{
		shouldIgnoreMounts: false,
		ignorePrefixes:     []string{},
		includePrefixes:    []string{},
	}
}

func (rule *R0002UnexpectedFileAccess) Name() string {
	return R0002Name
}
func (rule *R0002UnexpectedFileAccess) ID() string {
	return R0002ID
}

func (rule *R0002UnexpectedFileAccess) SetParameters(parameters map[string]interface{}) {
	rule.BaseRule.SetParameters(parameters)

	rule.shouldIgnoreMounts = fmt.Sprintf("%v", rule.GetParameters()["ignoreMounts"]) == "true"

	ignorePrefixesInterface := rule.GetParameters()["ignorePrefixes"]
	if ignorePrefixesInterface != nil {
		ignorePrefixes, ok := InterfaceToStringSlice(ignorePrefixesInterface)
		if ok {
			rule.ignorePrefixes = ignorePrefixes
		} else {
			logger.L().Warning("failed to convert ignorePrefixes to []string", helpers.String("ruleID", rule.ID()))
		}
	}

	includePrefixesInterface := rule.GetParameters()["includePrefixes"]
	if includePrefixesInterface != nil {
		includePrefixes, ok := InterfaceToStringSlice(includePrefixesInterface)
		if ok {
			rule.includePrefixes = includePrefixes
		} else {
			logger.L().Warning("failed to convert includePrefixes to []string", helpers.String("ruleID", rule.ID()))
		}
	}

}

func (rule *R0002UnexpectedFileAccess) DeleteRule() {
}

func (rule *R0002UnexpectedFileAccess) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache) ruleengine.DetectionResult {
	if eventType != utils.OpenEventType {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	fullEvent, ok := event.(*events.OpenEvent)
	if !ok {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	openEvent := fullEvent.Event

	// Check if we have include prefixes and if the path is not in the include prefixes, return nil
	if len(rule.includePrefixes) > 0 {
		include := false
		for _, prefix := range rule.includePrefixes {
			if strings.HasPrefix(openEvent.FullPath, prefix) {
				include = true
			}
		}
		if !include {
			return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
		}
	}

	// Check if path is ignored
	for _, prefix := range rule.ignorePrefixes {
		if strings.HasPrefix(openEvent.FullPath, prefix) {
			return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
		}
	}

	if rule.shouldIgnoreMounts {
		mounts, err := GetContainerMountPaths(openEvent.GetNamespace(), openEvent.GetPod(), openEvent.GetContainer(), k8sObjCache)
		if err != nil {
			return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
		}
		for _, mount := range mounts {
			if isPathContained(mount, openEvent.FullPath) {
				return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
			}
		}
	}

	return ruleengine.DetectionResult{IsFailure: true, Payload: openEvent.FullPath}
}

func (rule *R0002UnexpectedFileAccess) EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (ruleengine.DetectionResult, error) {
	// First do basic evaluation
	detectionResult := rule.EvaluateRule(eventType, event, objCache.K8sObjectCache())
	if !detectionResult.IsFailure {
		return detectionResult, nil
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
			found := 0
			for _, eventOpenFlag := range openEventTyped.Flags {
				// Check that event open flag is in the open.Flags
				for _, profileOpenFlag := range open.Flags {
					if eventOpenFlag == profileOpenFlag {
						found += 1
					}
				}
			}
			if found == len(openEventTyped.Flags) {
				return ruleengine.DetectionResult{IsFailure: false, Payload: open.Path}, nil
			}
		}
	}

	return detectionResult, nil
}

func (rule *R0002UnexpectedFileAccess) CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache, payload ruleengine.DetectionResult) ruleengine.RuleFailure {
	openEvent, _ := event.(*events.OpenEvent)
	openEventTyped := openEvent.Event

	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:    HashStringToMD5(fmt.Sprintf("%s%s", openEventTyped.Comm, openEventTyped.FullPath)),
			AlertName:   rule.Name(),
			InfectedPID: openEventTyped.Pid,
			Arguments: map[string]interface{}{
				"flags": openEventTyped.Flags,
				"path":  openEventTyped.FullPath,
			},
			Severity: R0002UnexpectedFileAccessRuleDescriptor.Priority,
			Identifiers: &common.Identifiers{
				Process: &common.ProcessEntity{
					Name: openEventTyped.Comm,
				},
				File: &common.FileEntity{
					Name:      openEventTyped.FullPath,
					Directory: filepath.Dir(openEventTyped.FullPath),
				},
			},
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				Comm: openEventTyped.Comm,
				Gid:  &openEventTyped.Gid,
				PID:  openEventTyped.Pid,
				Uid:  &openEventTyped.Uid,
			},
			ContainerID: openEventTyped.Runtime.ContainerID,
		},
		TriggerEvent: openEventTyped.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: fmt.Sprintf("Unexpected file access: %s with flags %s", openEventTyped.FullPath, strings.Join(openEventTyped.Flags, ",")),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName: openEventTyped.GetPod(),
		},
		RuleID: rule.ID(),
		Extra:  openEvent.GetExtra(),
	}
}

func isPathContained(basepath, targetpath string) bool {
	return strings.HasPrefix(targetpath, basepath)
}

func (rule *R0002UnexpectedFileAccess) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R0002UnexpectedFileAccessRuleDescriptor.Requirements.RequiredEventTypes(),
		ProfileRequirements: ruleengine.ProfileRequirement{
			ProfileDependency: apitypes.Required,
			ProfileType:       apitypes.ApplicationProfile,
		},
	}
}
