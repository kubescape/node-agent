package ruleengine

import (
	"fmt"
	"path/filepath"
	"strings"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	R0008ID   = "R0008"
	R0008Name = "Read Environment Variables from procfs"
)

var R0008ReadEnvironmentVariablesProcFSRuleDescriptor = ruleengine.RuleDescriptor{
	ID:          R0008ID,
	Name:        R0008Name,
	Description: "Detecting reading environment variables from procfs.",
	Tags:        []string{"env", "malicious", "whitelisted"},
	Priority:    RulePriorityMed,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.OpenEventType,
		},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR0008ReadEnvironmentVariablesProcFS()
	},
}
var _ ruleengine.RuleEvaluator = (*R0008ReadEnvironmentVariablesProcFS)(nil)

type R0008ReadEnvironmentVariablesProcFS struct {
	BaseRule
	alertedPaths map[string]bool
}

func CreateRuleR0008ReadEnvironmentVariablesProcFS() *R0008ReadEnvironmentVariablesProcFS {
	return &R0008ReadEnvironmentVariablesProcFS{
		alertedPaths: make(map[string]bool),
	}
}
func (rule *R0008ReadEnvironmentVariablesProcFS) Name() string {
	return R0008Name
}

func (rule *R0008ReadEnvironmentVariablesProcFS) ID() string {
	return R0008ID
}

func (rule *R0008ReadEnvironmentVariablesProcFS) DeleteRule() {
}

func (rule *R0008ReadEnvironmentVariablesProcFS) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache) ruleengine.DetectionResult {
	if eventType != utils.OpenEventType {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	fullEvent, ok := event.(*events.OpenEvent)
	if !ok {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	openEvent := fullEvent.Event

	if !strings.HasPrefix(openEvent.FullPath, "/proc/") || !strings.HasSuffix(openEvent.FullPath, "/environ") {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	if rule.alertedPaths[openEvent.FullPath] {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	return ruleengine.DetectionResult{IsFailure: true, Payload: openEvent.FullPath}
}

func (rule *R0008ReadEnvironmentVariablesProcFS) EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (ruleengine.DetectionResult, error) {
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
		// Check if there is an open call to /proc/<pid>/environ
		if strings.HasPrefix(open.Path, "/proc/") && strings.HasSuffix(open.Path, "/environ") {
			return ruleengine.DetectionResult{IsFailure: false, Payload: open.Path}, nil
		}
	}

	return detectionResult, nil
}

func (rule *R0008ReadEnvironmentVariablesProcFS) CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache, payload ruleengine.DetectionResult) ruleengine.RuleFailure {
	fullEvent, _ := event.(*events.OpenEvent)
	openEvent := fullEvent.Event

	rule.alertedPaths[openEvent.FullPath] = true

	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:  HashStringToMD5(fmt.Sprintf("%s%s", openEvent.Comm, openEvent.FullPath)),
			AlertName: rule.Name(),
			Arguments: map[string]interface{}{
				"path":  openEvent.FullPath,
				"flags": openEvent.Flags,
			},
			InfectedPID: openEvent.Pid,
			Severity:    R0008ReadEnvironmentVariablesProcFSRuleDescriptor.Priority,
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
			RuleDescription: fmt.Sprintf("Reading environment variables from procfs: %s", openEvent.GetContainer()),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:   openEvent.GetPod(),
			PodLabels: openEvent.K8s.PodLabels,
		},
		RuleID: rule.ID(),
		Extra:  fullEvent.GetExtra(),
	}
}

func (rule *R0008ReadEnvironmentVariablesProcFS) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R0008ReadEnvironmentVariablesProcFSRuleDescriptor.Requirements.RequiredEventTypes(),
		ProfileRequirements: ruleengine.ProfileRequirement{
			ProfileDependency: apitypes.Required,
			ProfileType:       apitypes.ApplicationProfile,
		},
	}
}
