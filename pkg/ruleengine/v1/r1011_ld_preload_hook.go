package ruleengine

import (
	"fmt"
	"os"
	"strings"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

const (
	R1011ID         = "R1011"
	R1011Name       = "LD_PRELOAD Hook"
	LD_PRELOAD_FILE = "/etc/ld.so.preload"
	JAVA_COMM       = "java"
)

var LD_PRELOAD_ENV_VARS = []string{"LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"}

var R1011LdPreloadHookRuleDescriptor = RuleDescriptor{
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

func (rule *R1011LdPreloadHook) handleExecEvent(execEvent *tracerexectype.Event, k8sObjCache objectcache.K8sObjectCache) ruleengine.RuleFailure {
	// Java is a special case, we don't want to alert on it because it uses LD_LIBRARY_PATH.
	if execEvent.Comm == JAVA_COMM {
		return nil
	}

	envVars, err := utils.GetProcessEnv(int(execEvent.Pid))
	if err != nil {
		logger.L().Debug("Failed to get process environment variables", helpers.Error(err))
		return nil
	}

	shouldCheck := false
	ldHookVar := ""
	for _, envVar := range LD_PRELOAD_ENV_VARS {
		if _, ok := envVars[envVar]; ok {
			shouldCheck = true
			ldHookVar = envVar
			break
		}
	}

	// Check if the environment variable is in the list of LD_PRELOAD_ENV_VARS
	if shouldCheck {
		// Check the pod spec for env vars that match the LD_PRELOAD_ENV_VARS
		podSpec := k8sObjCache.GetPodSpec(execEvent.GetNamespace(), execEvent.GetPod())
		if podSpec != nil {
			for _, container := range podSpec.Containers {
				if container.Name == execEvent.GetContainer() {
					for _, envVar := range container.Env {
						if envVar.Name == ldHookVar {
							// The environment variable is set in the pod spec
							return nil
						}
					}
				}
			}
		}

		upperLayer := execEvent.UpperLayer || execEvent.PupperLayer

		ruleFailure := GenericRuleFailure{
			BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
				AlertName:      rule.Name(),
				InfectedPID:    execEvent.Pid,
				FixSuggestions: fmt.Sprintf("Check the environment variable %s", ldHookVar),
				Severity:       R1011LdPreloadHookRuleDescriptor.Priority,
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
					Path:       getExecFullPathFromEvent(execEvent),
					Cmdline:    fmt.Sprintf("%s %s", getExecPathFromEvent(execEvent), strings.Join(utils.GetExecArgsFromEvent(execEvent), " ")),
				},
				ContainerID: execEvent.Runtime.ContainerID,
			},
			TriggerEvent: execEvent.Event,
			RuleAlert: apitypes.RuleAlert{
				RuleDescription: fmt.Sprintf("Process (%s) was executed in: %s and is using the environment variable %s", execEvent.Comm, execEvent.GetContainer(), fmt.Sprintf("%s=%s", ldHookVar, envVars[ldHookVar])),
			},
			RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
				PodName: execEvent.GetPod(),
			},
			RuleID: rule.ID(),
		}

		return &ruleFailure
	}

	return nil
}

func (rule *R1011LdPreloadHook) handleOpenEvent(openEvent *traceropentype.Event) ruleengine.RuleFailure {
	if openEvent.FullPath == LD_PRELOAD_FILE && (openEvent.FlagsRaw&(int32(os.O_WRONLY)|int32(os.O_RDWR))) != 0 {
		ruleFailure := GenericRuleFailure{
			BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
				AlertName:      rule.Name(),
				InfectedPID:    openEvent.Pid,
				FixSuggestions: "Check the file /etc/ld.so.preload",
				Severity:       R1011LdPreloadHookRuleDescriptor.Priority,
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
				RuleDescription: fmt.Sprintf("Process (%s) was executed in: %s and is opening the file %s", openEvent.Comm, openEvent.GetContainer(), openEvent.Path),
			},
			RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
				PodName: openEvent.GetPod(),
			},
			RuleID: rule.ID(),
		}

		return &ruleFailure
	}

	return nil
}

func (rule *R1011LdPreloadHook) ProcessEvent(eventType utils.EventType, event interface{}, objectCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.ExecveEventType && eventType != utils.OpenEventType {
		return nil
	}

	if eventType == utils.ExecveEventType {
		execEvent, ok := event.(*tracerexectype.Event)
		if !ok {
			return nil
		}

		return rule.handleExecEvent(execEvent, objectCache.K8sObjectCache())
	} else if eventType == utils.OpenEventType {
		openEvent, ok := event.(*traceropentype.Event)
		if !ok {
			return nil
		}

		return rule.handleOpenEvent(openEvent)
	}

	return nil
}

func (rule *R1011LdPreloadHook) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1011LdPreloadHookRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
