package ruleengine

import (
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/ruleengine/objectcache"
	"node-agent/pkg/utils"
	"strings"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	log "github.com/sirupsen/logrus"
)

const (
	R1004ID                    = "R1004"
	R1004ExecFromMountRuleName = "Exec from mount"
)

var R1004ExecFromMountRuleDescriptor = RuleDescriptor{
	ID:          R1004ID,
	Name:        R1004ExecFromMountRuleName,
	Description: "Detecting exec calls from mounted paths.",
	Tags:        []string{"exec", "mount"},
	Priority:    RulePriorityMed,
	Requirements: &RuleRequirements{
		EventTypes:             []utils.EventType{utils.ExecveEventType},
		NeedApplicationProfile: false,
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1004ExecFromMount()
	},
}

type R1004ExecFromMount struct {
	BaseRule
	// Map of container ID to mount paths
}

func CreateRuleR1004ExecFromMount() *R1004ExecFromMount {
	return &R1004ExecFromMount{}
}
func (rule *R1004ExecFromMount) Name() string {
	return R1004ExecFromMountRuleName
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
			log.Debugf("Path %s is mounted in pod %s/%s", p, execEvent.GetNamespace(), execEvent.GetPod())
			return &GenericRuleFailure{
				RuleName:         rule.Name(),
				RuleID:           rule.ID(),
				Err:              "Exec from mount",
				FailureEvent:     utils.ExecToGeneralEvent(execEvent),
				FixSuggestionMsg: "If this is a legitimate action, please consider removing this workload from the binding of this rule",
				RulePriority:     R1004ExecFromMountRuleDescriptor.Priority,
			}
		}
	}

	return nil

}

func (rule *R1004ExecFromMount) isPathContained(targetpath, basepath string) bool {
	return strings.HasPrefix(targetpath, basepath)
}

func (rule *R1004ExecFromMount) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes:             []utils.EventType{utils.ExecveEventType},
		NeedApplicationProfile: false,
	}
}
