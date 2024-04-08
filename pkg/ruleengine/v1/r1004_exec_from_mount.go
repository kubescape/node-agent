package ruleengine

import (
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"
	"strings"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
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
		contained := rule.isPathContained(p, mount)
		if contained {
			logger.L().Debug("Exec from mount", helpers.String("path", p), helpers.String("mount", mount))
			isPartOfImage := !execEvent.UpperLayer
			ruleFailure := GenericRuleFailure{
				BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
					AlertName:      rule.Name(),
					FixSuggestions: "If this is a legitimate action, please consider removing this workload from the binding of this rule",
					Severity:       R1004ExecFromMountRuleDescriptor.Priority,
					IsPartOfImage:  &isPartOfImage,
					PPID:           &execEvent.Ppid,
					PPIDComm:       &execEvent.Pcomm,
				},
				RuntimeProcessDetails: apitypes.RuntimeAlertProcessDetails{
					Comm: execEvent.Comm,
					GID:  execEvent.Gid,
					PID:  execEvent.Pid,
					UID:  execEvent.Uid,
				},
				TriggerEvent: execEvent.Event,
				RuleAlert: apitypes.RuleAlert{
					RuleID:          rule.ID(),
					RuleDescription: "Exec from mount",
				},
				RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{},
			}

			enrichRuleFailure(execEvent.Event, execEvent.Pid, &ruleFailure)

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
