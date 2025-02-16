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
	R3004ID          = "R3004"
	R3004Name        = "Docker Socket Accessed From Container"
	dockerSocketPath = "/var/run/docker.sock"
)

var R3004DockerSocketAccessRuleDescriptor = ruleengine.RuleDescriptor{
	ID:          R3004ID,
	Name:        R3004Name,
	Description: "Detecting attempts to access Docker socket which could indicate a container escape attempt",
	Tags:        []string{"container-escape", "privilege-escalation", "docker"},
	Priority:    ruleenginev1.RulePriorityMed,
	Requirements: &ruleenginev1.RuleRequirements{
		EventTypes: []utils.EventType{utils.OpenEventType},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR3004DockerSocketAccess()
	},
}

var _ ruleengine.RuleEvaluator = (*R3004DockerSocketAccess)(nil)

type R3004DockerSocketAccess struct {
	ruleenginev1.BaseRule
}

func CreateRuleR3004DockerSocketAccess() *R3004DockerSocketAccess {
	return &R3004DockerSocketAccess{}
}

func (rule *R3004DockerSocketAccess) Name() string {
	return R3004Name
}

func (rule *R3004DockerSocketAccess) ID() string {
	return R3004ID
}

func (rule *R3004DockerSocketAccess) SetParameters(parameters map[string]interface{}) {
	rule.BaseRule.SetParameters(parameters)
}

func (rule *R3004DockerSocketAccess) DeleteRule() {
}

func (rule *R3004DockerSocketAccess) ProcessEvent(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
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

	if !ComparePaths(openEvent.FullPath, dockerSocketPath) {
		return nil
	}

	if isAllowedNamespace(openEvent.GetNamespace()) {
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
			Severity: R3004DockerSocketAccessRuleDescriptor.Priority,
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
			RuleDescription: fmt.Sprintf("Container escape attempt detected: Access to Docker socket '%s' with flags %s in container: %s",
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

func (rule *R3004DockerSocketAccess) Requirements() ruleengine.RuleSpec {
	return &ruleenginev1.RuleRequirements{
		EventTypes: R3004DockerSocketAccessRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
