package ruleengine

import (
	"fmt"
	"os"
	"strings"

	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
)

const (
	R1011ID         = "R1011"
	R1011Name       = "LD_PRELOAD Hook"
	LD_PRELOAD_FILE = "/etc/ld.so.preload"
	JAVA_COMM       = "java"
)

var LD_PRELOAD_ENV_VARS = []string{"LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"}

var R1011LdPreloadHookRuleDescriptor = ruleengine.RuleDescriptor{
	ID:          R1011ID,
	Name:        R1011Name,
	Description: "Detecting ld_preload hook techniques.",
	Tags:        []string{"exec", "malicious"},
	Priority:    RulePriorityMed,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.ExecveEventType,
			utils.OpenEventType,
		},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1011LdPreloadHook()
	},
	RulePolicySupport: true,
}
var _ ruleengine.RuleEvaluator = (*R1011LdPreloadHook)(nil)

type R1011LdPreloadHook struct {
	BaseRule
}

func CreateRuleR1011LdPreloadHook() *R1011LdPreloadHook {
	return &R1011LdPreloadHook{}
}

func (rule *R1011LdPreloadHook) Name() string {
	return R1011Name
}

func (rule *R1011LdPreloadHook) ID() string {
	return R1011ID
}

func (rule *R1011LdPreloadHook) DeleteRule() {
}

func (rule *R1011LdPreloadHook) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache) ruleengine.DetectionResult {
	switch eventType {
	case utils.ExecveEventType:
		execEvent, ok := event.(*events.ExecEvent)
		if !ok {
			return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
		}
		return rule.shouldAlertExec(execEvent, k8sObjCache)

	case utils.OpenEventType:
		openEvent, ok := event.(*events.OpenEvent)
		if !ok {
			return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
		}
		return rule.shouldAlertOpen(openEvent)

	default:
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}
}

func (rule *R1011LdPreloadHook) EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (ruleengine.DetectionResult, error) {
	// First do basic evaluation
	detectionResult := rule.EvaluateRule(eventType, event, objCache.K8sObjectCache())
	if !detectionResult.IsFailure {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, nil
	}

	switch eventType {
	case utils.ExecveEventType:
		execEvent, _ := event.(*events.ExecEvent)
		if allowed, err := IsAllowed(&execEvent.Event.Event, objCache, execEvent.Comm, R1011ID); err != nil {
			return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, err
		} else if allowed {
			return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, nil
		}
		return ruleengine.DetectionResult{IsFailure: true, Payload: nil}, nil

	case utils.OpenEventType:
		openEvent, _ := event.(*events.OpenEvent)
		if allowed, err := IsAllowed(&openEvent.Event.Event, objCache, openEvent.Comm, R1011ID); err != nil {
			return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, err
		} else if allowed {
			return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, nil
		}
		return ruleengine.DetectionResult{IsFailure: true, Payload: nil}, nil

	default:
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, nil
	}
}

func (rule *R1011LdPreloadHook) CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache, payload ruleengine.DetectionResult) ruleengine.RuleFailure {
	switch eventType {
	case utils.ExecveEventType:
		execEvent, _ := event.(*events.ExecEvent)
		return rule.ruleFailureExecEvent(execEvent)

	case utils.OpenEventType:
		openEvent, _ := event.(*events.OpenEvent)
		return rule.ruleFailureOpenEvent(&openEvent.Event, openEvent.GetExtra())

	default:
		return nil
	}
}

func (rule *R1011LdPreloadHook) ruleFailureExecEvent(execEvent *events.ExecEvent) ruleengine.RuleFailure {
	envVars, err := utils.GetProcessEnv(int(execEvent.Pid))
	if err != nil {
		return nil
	}

	ldHookVar, _ := GetLdHookVar(envVars)

	upperLayer := execEvent.UpperLayer || execEvent.PupperLayer

	ruleFailure := GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:    HashStringToMD5(fmt.Sprintf("%s%s%s", execEvent.Comm, execEvent.ExePath, execEvent.Pcomm)),
			AlertName:   rule.Name(),
			Arguments:   map[string]interface{}{"envVar": ldHookVar},
			InfectedPID: execEvent.Pid,
			Severity:    R1011LdPreloadHookRuleDescriptor.Priority,
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
				Path:       GetExecFullPathFromEvent(execEvent),
				Cmdline:    fmt.Sprintf("%s %s", GetExecPathFromEvent(execEvent), strings.Join(utils.GetExecArgsFromEvent(&execEvent.Event), " ")),
			},
			ContainerID: execEvent.Runtime.ContainerID,
		},
		TriggerEvent: execEvent.Event.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: fmt.Sprintf("Process (%s) was executed and is using the environment variable %s", execEvent.Comm, fmt.Sprintf("%s=%s", ldHookVar, envVars[ldHookVar])),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:   execEvent.GetPod(),
			PodLabels: execEvent.K8s.PodLabels,
		},
		RuleID: rule.ID(),
		Extra:  execEvent.GetExtra(),
	}

	return &ruleFailure
}

func (rule *R1011LdPreloadHook) ruleFailureOpenEvent(openEvent *traceropentype.Event, extra interface{}) ruleengine.RuleFailure {
	ruleFailure := GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:  HashStringToMD5(fmt.Sprintf("%s%s", openEvent.Comm, openEvent.FullPath)),
			AlertName: rule.Name(),
			Arguments: map[string]interface{}{
				"path":  openEvent.FullPath,
				"flags": openEvent.Flags,
			},
			InfectedPID: openEvent.Pid,
			Severity:    R1011LdPreloadHookRuleDescriptor.Priority,
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
			RuleDescription: fmt.Sprintf("Process (%s) was executed and is opening the file %s", openEvent.Comm, openEvent.Path),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:   openEvent.GetPod(),
			PodLabels: openEvent.K8s.PodLabels,
		},
		RuleID: rule.ID(),
		Extra:  extra,
	}

	return &ruleFailure
}

func (rule *R1011LdPreloadHook) shouldAlertExec(execEvent *events.ExecEvent, k8sObjCache objectcache.K8sObjectCache) ruleengine.DetectionResult {
	// Java is a special case, we don't want to alert on it because it uses LD_LIBRARY_PATH.
	if execEvent.Comm == JAVA_COMM {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	// Check if the process is a MATLAB process and ignore it.
	if execEvent.GetContainer() == "matlab" {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	envVars, err := utils.GetProcessEnv(int(execEvent.Pid))
	if err != nil {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	ldHookVar, shouldCheck := GetLdHookVar(envVars)
	if shouldCheck {
		if k8sObjCache == nil {
			return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
		}

		podSpec := k8sObjCache.GetPodSpec(execEvent.GetNamespace(), execEvent.GetPod())
		if podSpec != nil {
			for _, container := range podSpec.Containers {
				if container.Name == execEvent.GetContainer() {
					for _, envVar := range container.Env {
						if envVar.Name == ldHookVar {
							return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
						}
					}
				}
			}
		}
		return ruleengine.DetectionResult{IsFailure: true, Payload: nil}
	}

	return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
}

func (rule *R1011LdPreloadHook) shouldAlertOpen(openEvent *events.OpenEvent) ruleengine.DetectionResult {
	if openEvent.FullPath == LD_PRELOAD_FILE && (openEvent.FlagsRaw&(int32(os.O_WRONLY)|int32(os.O_RDWR))) != 0 {
		return ruleengine.DetectionResult{IsFailure: true, Payload: nil}
	}
	return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
}

func GetLdHookVar(envVars map[string]string) (string, bool) {
	for _, envVar := range LD_PRELOAD_ENV_VARS {
		if _, ok := envVars[envVar]; ok {
			return envVar, true
		}
	}
	return "", false
}

func (rule *R1011LdPreloadHook) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1011LdPreloadHookRuleDescriptor.Requirements.RequiredEventTypes(),
		ProfileRequirements: ruleengine.ProfileRequirement{
			ProfileDependency: apitypes.Optional,
			ProfileType:       apitypes.ApplicationProfile,
		},
	}
}
