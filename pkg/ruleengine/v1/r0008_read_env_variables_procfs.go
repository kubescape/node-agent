package ruleengine

import (
	"fmt"
	"strings"

	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
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
}

func CreateRuleR0008ReadEnvironmentVariablesProcFS() *R0008ReadEnvironmentVariablesProcFS {
	return &R0008ReadEnvironmentVariablesProcFS{}
}
func (rule *R0008ReadEnvironmentVariablesProcFS) Name() string {
	return R0008Name
}

func (rule *R0008ReadEnvironmentVariablesProcFS) ID() string {
	return R0008ID
}

func (rule *R0008ReadEnvironmentVariablesProcFS) DeleteRule() {
}

func (rule *R0008ReadEnvironmentVariablesProcFS) ProcessEvent(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.OpenEventType {
		return nil
	}

	fullEvent, ok := event.(*events.OpenEvent)
	if !ok {
		return nil
	}

	openEvent := fullEvent.Event

	if !strings.HasPrefix(openEvent.FullPath, "/proc/") || !strings.HasSuffix(openEvent.FullPath, "/environ") {
		return nil
	}

	if objCache != nil {
		ap := objCache.ApplicationProfileCache().GetApplicationProfile(openEvent.Runtime.ContainerID)
		if ap == nil {
			return nil
		}

		appProfileOpenList, err := GetContainerFromApplicationProfile(ap, openEvent.GetContainer())
		if err != nil {
			return nil
		}

		for _, open := range appProfileOpenList.Opens {
			// Check if there is an open call to /proc/<pid>/environ
			if strings.HasPrefix(open.Path, "/proc/") && strings.HasSuffix(open.Path, "/environ") {
				return nil
			}
		}
	}

	ruleFailure := GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName: rule.Name(),
			Arguments: map[string]interface{}{
				"path":  openEvent.FullPath,
				"flags": openEvent.Flags,
			},
			InfectedPID: openEvent.Pid,
			Severity:    R0008ReadEnvironmentVariablesProcFSRuleDescriptor.Priority,
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

	return &ruleFailure
}

func (rule *R0008ReadEnvironmentVariablesProcFS) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R0008ReadEnvironmentVariablesProcFSRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
