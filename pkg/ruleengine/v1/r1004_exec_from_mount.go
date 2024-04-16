package ruleengine

import (
	"fmt"
	"node-agent/pkg/objectcache"
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/utils"
	"strings"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
)

const (
	R1004ID   = "R1004"
	R1004Name = "Exec from mount"
)

var R1004ExecFromMountRuleDescriptor = RuleDescriptor{
	ID:          R1004ID,
	Name:        R1004Name,
	Description: "Detecting exec calls from mounted paths.",
	Tags:        []string{"exec", "mount"},
	Priority:    RulePriorityMed,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{utils.ExecveEventType},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1004ExecFromMount()
	},
}

type R1004ExecFromMount struct {
	BaseRule
}

func CreateRuleR1004ExecFromMount() *R1004ExecFromMount {
	return &R1004ExecFromMount{}
}
func (rule *R1004ExecFromMount) Name() string {
	return R1004Name
}

func (rule *R1004ExecFromMount) ID() string {
	return R1004ID
}

func (rule *R1004ExecFromMount) DeleteRule() {
}

func (rule *R1004ExecFromMount) ProcessEvent(eventType utils.EventType, event interface{}, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.ExecveEventType {
		return nil
	}

	execEvent, ok := event.(*tracerexectype.Event)
	if !ok {
		return nil
	}

	mounts, err := getContainerMountPaths(execEvent.GetNamespace(), execEvent.GetPod(), execEvent.GetContainer(), objCache.K8sObjectCache())
	if err != nil {
		return nil
	}

	for _, mount := range mounts {
		p := getExecPathFromEvent(execEvent)
		if rule.isPathContained(p, mount) || rule.isPathContained(execEvent.ExePath, mount) {
			ruleFailure := GenericRuleFailure{
				BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
					AlertName:   rule.Name(),
					InfectedPID: execEvent.Pid,
					Arguments: map[string]interface{}{
						"hardlink": execEvent.ExePath,
					},
					FixSuggestions: "If this is a legitimate action, please consider removing this workload from the binding of this rule",
					Severity:       R1004ExecFromMountRuleDescriptor.Priority,
				},
				RuntimeProcessDetails: apitypes.ProcessTree{
					ProcessTree: apitypes.Process{
						Comm:       execEvent.Comm,
						Gid:        &execEvent.Gid,
						PID:        execEvent.Pid,
						Uid:        &execEvent.Uid,
						UpperLayer: execEvent.UpperLayer,
						PPID:       execEvent.Ppid,
						Pcomm:      execEvent.Pcomm,
						Cwd:        execEvent.Cwd,
						Hardlink:   execEvent.ExePath,
						Cmdline:    fmt.Sprintf("%s %s", p, strings.Join(utils.GetExecArgsFromEvent(execEvent), " ")),
					},
					ContainerID: execEvent.Runtime.ContainerID,
				},
				TriggerEvent: execEvent.Event,
				RuleAlert: apitypes.RuleAlert{
					RuleID:          rule.ID(),
					RuleDescription: fmt.Sprintf("Process (%s) was executed from a mounted path (%s) in: %s", p, mount, execEvent.GetContainer()),
				},
				RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
					PodName: execEvent.GetPod(),
				},
			}

			return &ruleFailure
		}
	}

	return nil
}

func (rule *R1004ExecFromMount) isPathContained(targetpath, basepath string) bool {
	return strings.HasPrefix(targetpath, basepath)
}

func (rule *R1004ExecFromMount) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1004ExecFromMountRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
