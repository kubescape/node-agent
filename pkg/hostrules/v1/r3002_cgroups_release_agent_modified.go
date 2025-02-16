package hostrules

import (
	"fmt"
	"strings"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	ruleenginev1 "github.com/kubescape/node-agent/pkg/ruleengine/v1"
	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	R3002ID   = "R3002"
	R3002Name = "CGroups Release Agent Modified"
)

var R3002CGroupsReleaseAgentModifiedRuleDescriptor = ruleengine.RuleDescriptor{
	ID:          R3002ID,
	Name:        R3002Name,
	Description: "Detecting attempts to modify control group (cgroup) release agent files which could indicate a container escape attempt",
	Tags:        []string{"container-escape", "privilege-escalation", "cgroups"},
	Priority:    ruleenginev1.RulePriorityHigh,
	Requirements: &ruleenginev1.RuleRequirements{
		EventTypes: []utils.EventType{utils.OpenEventType},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR3002CGroupsReleaseAgent()
	},
}

var _ ruleengine.RuleEvaluator = (*R3002CGroupsReleaseAgent)(nil)

type R3002CGroupsReleaseAgent struct {
	ruleenginev1.BaseRule
}

func CreateRuleR3002CGroupsReleaseAgent() *R3002CGroupsReleaseAgent {
	return &R3002CGroupsReleaseAgent{}
}

func (rule *R3002CGroupsReleaseAgent) Name() string {
	return R3002Name
}

func (rule *R3002CGroupsReleaseAgent) ID() string {
	return R3002ID
}

func (rule *R3002CGroupsReleaseAgent) SetParameters(parameters map[string]interface{}) {
	rule.BaseRule.SetParameters(parameters)
}

func (rule *R3002CGroupsReleaseAgent) DeleteRule() {
}

func (rule *R3002CGroupsReleaseAgent) ProcessEvent(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.OpenEventType {
		return nil
	}

	fullEvent, ok := event.(*events.OpenEvent)
	if !ok {
		return nil
	}

	openEvent := fullEvent.Event

	if openEvent.Runtime.ContainerID == "" {
		return nil
	}

	if !ComparePaths(openEvent.FullPath, "/sys/fs/cgroup/memory/release_agent") &&
		!ComparePaths(openEvent.FullPath, "/sys/fs/cgroup/release_agent") {
		return nil
	}

	if !hasTargetFlags(openEvent.Flags, writeFlags) {
		return nil
	}

	ruleFailure := ruleenginev1.GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName:   rule.Name(),
			InfectedPID: openEvent.Pid,
			Arguments: map[string]interface{}{
				"flags": openEvent.Flags,
				"path":  openEvent.FullPath,
			},
			Severity: R3002CGroupsReleaseAgentModifiedRuleDescriptor.Priority,
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
			RuleDescription: fmt.Sprintf("Container escape attempt detected: Modification of cgroups release_agent file '%s' with flags %s in container: %s",
				openEvent.FullPath,
				strings.Join(openEvent.Flags, ","),
				openEvent.GetContainer()),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName: openEvent.GetPod(),
		},
		RuleID: rule.ID(),
		Extra:  fullEvent.GetExtra(),
	}

	return &ruleFailure
}

func (rule *R3002CGroupsReleaseAgent) Requirements() ruleengine.RuleSpec {
	return &ruleenginev1.RuleRequirements{
		EventTypes: R3002CGroupsReleaseAgentModifiedRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
