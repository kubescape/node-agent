package ruleengine

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
)

const (
	R1000ID   = "R1000"
	R1000Name = "Exec from malicious source"
)

var R1000ExecFromMaliciousSourceDescriptor = ruleengine.RuleDescriptor{
	ID:          R1000ID,
	Name:        R1000Name,
	Description: "Detecting exec calls that are from malicious source like: /dev/shm, /proc/self",
	Priority:    RulePriorityMed,
	Tags:        []string{"exec", "signature"},
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{utils.ExecveEventType},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1000ExecFromMaliciousSource()
	},
}
var _ ruleengine.RuleEvaluator = (*R1000ExecFromMaliciousSource)(nil)

type R1000ExecFromMaliciousSource struct {
	BaseRule
}

func CreateRuleR1000ExecFromMaliciousSource() *R1000ExecFromMaliciousSource {
	return &R1000ExecFromMaliciousSource{}
}

func (rule *R1000ExecFromMaliciousSource) Name() string {
	return R1000Name
}

func (rule *R1000ExecFromMaliciousSource) ID() string {
	return R1000ID
}

var whitelistedProcessesForMaliciousSource = []string{
	"systemd",
	"docker",
	"containerd",
	"snap-confine",
	"nginx",
	"apache2",
	"bash",
	"dash",
	"sh",
	"supervisord",
}

func (rule *R1000ExecFromMaliciousSource) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache) ruleengine.DetectionResult {
	if eventType != utils.ExecveEventType {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	execEvent, ok := event.(*events.ExecEvent)
	if !ok {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	var maliciousExecPathPrefixes = []string{
		"/dev/shm",
	}

	// Running without object cache, to avoid false positives check if the process name is legitimate
	if k8sObjCache == nil {
		for _, processName := range whitelistedProcessesForMaliciousSource {
			if processName == execEvent.Comm {
				return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
			}
		}
	}

	execPath := GetExecFullPathFromEvent(execEvent)
	execPathDir := filepath.Dir(execPath)
	for _, maliciousExecPathPrefix := range maliciousExecPathPrefixes {
		if strings.HasPrefix(execPathDir, maliciousExecPathPrefix) ||
			strings.HasPrefix(execEvent.Cwd, maliciousExecPathPrefix) ||
			strings.HasPrefix(execEvent.ExePath, maliciousExecPathPrefix) {
			return ruleengine.DetectionResult{IsFailure: true, Payload: execEvent}
		}
	}

	return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
}

func (rule *R1000ExecFromMaliciousSource) EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (ruleengine.DetectionResult, error) {
	detectionResult := rule.EvaluateRule(eventType, event, objCache.K8sObjectCache())
	if !detectionResult.IsFailure {
		return detectionResult, nil
	}
	// This rule doesn't need profile evaluation since it's based on direct detection
	return ruleengine.DetectionResult{IsFailure: true, Payload: nil}, nil
}

func (rule *R1000ExecFromMaliciousSource) CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache, payload ruleengine.DetectionResult) ruleengine.RuleFailure {
	execEvent, _ := event.(*events.ExecEvent)
	execPath := GetExecFullPathFromEvent(execEvent)
	execPathDir := filepath.Dir(execPath)
	upperLayer := execEvent.UpperLayer || execEvent.PupperLayer

	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:    HashStringToMD5(fmt.Sprintf("%s%s%s", execEvent.Comm, execPath, execEvent.Pcomm)),
			AlertName:   rule.Name(),
			InfectedPID: execEvent.Pid,
			Arguments: map[string]interface{}{
				"hardlink": execEvent.ExePath,
			},
			Severity: R1000ExecFromMaliciousSourceDescriptor.Priority,
			Identifiers: &common.Identifiers{
				Process: &common.ProcessEntity{
					Name:        execEvent.Comm,
					CommandLine: fmt.Sprintf("%s %s", execPath, strings.Join(utils.GetExecArgsFromEvent(&execEvent.Event), " ")),
				},
				File: &common.FileEntity{
					Name:      filepath.Base(execPath),
					Directory: filepath.Dir(execPath),
				},
			},
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				Comm:       execEvent.Comm,
				Gid:        &execEvent.Gid,
				PID:        execEvent.Pid,
				Uid:        &execEvent.Uid,
				UpperLayer: &upperLayer,
				PPID:       execEvent.Ppid,
				Pcomm:      execEvent.Pcomm,
				Cwd:        execEvent.Cwd,
				Hardlink:   execEvent.ExePath,
				Path:       execPath,
				Cmdline:    fmt.Sprintf("%s %s", GetExecPathFromEvent(execEvent), strings.Join(utils.GetExecArgsFromEvent(&execEvent.Event), " ")),
			},
			ContainerID: execEvent.Runtime.ContainerID,
		},
		TriggerEvent: execEvent.Event.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: fmt.Sprintf("Execution from malicious source: %s", execPathDir),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:   execEvent.GetPod(),
			PodLabels: execEvent.K8s.PodLabels,
		},
		RuleID: rule.ID(),
		Extra:  execEvent.GetExtra(),
	}
}

func (rule *R1000ExecFromMaliciousSource) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1000ExecFromMaliciousSourceDescriptor.Requirements.RequiredEventTypes(),
		ProfileRequirements: ruleengine.ProfileRequirement{
			ProfileDependency: apitypes.NotRequired,
			ProfileType:       apitypes.ApplicationProfile,
		},
	}
}
