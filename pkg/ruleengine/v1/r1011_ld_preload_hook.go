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

func (rule *R1011LdPreloadHook) ProcessEvent(eventType utils.EventType, event utils.K8sEvent, objectCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if ok, _ := rule.EvaluateRule(eventType, event, objectCache.K8sObjectCache()); !ok {
		return nil
	}

	if eventType == utils.ExecveEventType {
		execEvent, ok := event.(*events.ExecEvent)
		if !ok {
			return nil
		}

		if allowed, err := IsAllowed(&execEvent.Event.Event, objectCache, execEvent.Comm, R1011ID); err != nil {
			return nil
		} else if allowed {
			return nil
		}

		return rule.ruleFailureExecEvent(execEvent)
	} else if eventType == utils.OpenEventType {
		openEvent, ok := event.(*events.OpenEvent)
		if !ok {
			return nil
		}

		if allowed, err := IsAllowed(&openEvent.Event.Event, objectCache, openEvent.Comm, R1011ID); err != nil {
			return nil
		} else if allowed {
			return nil
		}

		return rule.ruleFailureOpenEvent(&openEvent.Event, openEvent.GetExtra())
	}

	return nil
}

func (rule *R1011LdPreloadHook) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache) (bool, interface{}) {
	switch eventType {
	case utils.ExecveEventType:
		execEvent, ok := event.(*events.ExecEvent)
		if !ok {
			return false, nil
		}
		return rule.shouldAlertExec(execEvent, k8sObjCache), nil

	case utils.OpenEventType:
		openEvent, ok := event.(*events.OpenEvent)
		if !ok {
			return false, nil
		}
		return rule.shouldAlertOpen(openEvent), nil

	default:
		return false, nil
	}
}

func (rule *R1011LdPreloadHook) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1011LdPreloadHookRuleDescriptor.Requirements.RequiredEventTypes(),
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

func (rule *R1011LdPreloadHook) shouldAlertExec(execEvent *events.ExecEvent, k8sObjCache objectcache.K8sObjectCache) bool {
	// Java is a special case, we don't want to alert on it because it uses LD_LIBRARY_PATH.
	if execEvent.Comm == JAVA_COMM {
		return false
	}

	// Check if the process is a MATLAB process and ignore it.
	if execEvent.GetContainer() == "matlab" {
		return false
	}

	envVars, err := utils.GetProcessEnv(int(execEvent.Pid))
	if err != nil {
		return false
	}

	ldHookVar, shouldCheck := GetLdHookVar(envVars)
	if shouldCheck {
		podSpec := k8sObjCache.GetPodSpec(execEvent.GetNamespace(), execEvent.GetPod())
		if podSpec != nil {
			for _, container := range podSpec.Containers {
				if container.Name == execEvent.GetContainer() {
					for _, envVar := range container.Env {
						if envVar.Name == ldHookVar {
							return false
						}
					}
				}
			}
		}
		return true
	}

	return false
}

func (rule *R1011LdPreloadHook) shouldAlertOpen(openEvent *events.OpenEvent) bool {
	return openEvent.FullPath == LD_PRELOAD_FILE && (openEvent.FlagsRaw&(int32(os.O_WRONLY)|int32(os.O_RDWR))) != 0
}

func GetLdHookVar(envVars map[string]string) (string, bool) {
	for _, envVar := range LD_PRELOAD_ENV_VARS {
		if _, ok := envVars[envVar]; ok {
			return envVar, true
		}
	}
	return "", false
}
