package hostrules

import (
	"fmt"
	"path/filepath"
	"strings"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	ruleenginev1 "github.com/kubescape/node-agent/pkg/ruleengine/v1"
	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	R3005ID   = "R3005"
	R3005Name = "Malicious Process Memory Injection From Filesystem"
)

var R3005MaliciousFsMemoryInjectionRuleDescriptor = ruleengine.RuleDescriptor{
	ID:          R3005ID,
	Name:        R3005Name,
	Description: "Detecting malicious attempts to inject code into process memory through /proc/PID/mem which indicates a potential process injection attack",
	Tags:        []string{"process-injection", "defense-evasion", "privilege-escalation"},
	Priority:    ruleenginev1.RulePriorityHigh,
	Requirements: &ruleenginev1.RuleRequirements{
		EventTypes: []utils.EventType{utils.OpenEventType},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR3005MaliciousFsMemoryInjection()
	},
}

var _ ruleengine.RuleEvaluator = (*R3005MaliciousFsMemoryInjection)(nil)

type R3005MaliciousFsMemoryInjection struct {
	ruleenginev1.BaseRule
}

func CreateRuleR3005MaliciousFsMemoryInjection() *R3005MaliciousFsMemoryInjection {
	return &R3005MaliciousFsMemoryInjection{}
}

func (rule *R3005MaliciousFsMemoryInjection) Name() string {
	return R3005Name
}

func (rule *R3005MaliciousFsMemoryInjection) ID() string {
	return R3005ID
}

func (rule *R3005MaliciousFsMemoryInjection) SetParameters(parameters map[string]interface{}) {
	rule.BaseRule.SetParameters(parameters)
}

func (rule *R3005MaliciousFsMemoryInjection) DeleteRule() {
}

func isProcMemPath(path string) bool {
	dir, file := filepath.Split(filepath.Clean(path))
	if file != "mem" {
		return false
	}

	dir = filepath.Clean(dir)
	parent, pid := filepath.Split(dir)

	parent = filepath.Clean(parent)

	if parent != "proc" && parent != "/proc" {
		return false
	}

	for _, char := range pid {
		if char < '0' || char > '9' {
			return false
		}
	}

	return true
}

func (rule *R3005MaliciousFsMemoryInjection) ProcessEvent(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.OpenEventType {
		return nil
	}

	fullEvent, ok := event.(*events.OpenEvent)
	if !ok {
		return nil
	}

	openEvent := fullEvent.Event

	if !isProcMemPath(openEvent.FullPath) {
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
			Severity: R3005MaliciousFsMemoryInjectionRuleDescriptor.Priority,
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
			RuleDescription: fmt.Sprintf("Process memory injection attempt detected: Write access to process memory via '%s' with flags %s from PID: %d",
				openEvent.FullPath,
				strings.Join(openEvent.Flags, ","),
				openEvent.Pid),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:       openEvent.GetPod(),
			ContainerID:   openEvent.Runtime.ContainerID,
			ContainerName: openEvent.GetContainer(),
			Namespace:     openEvent.GetNamespace(),
		},
		RuleID: rule.ID(),
		Extra:  fullEvent.GetExtra(),
	}

	return &ruleFailure
}

func (rule *R3005MaliciousFsMemoryInjection) Requirements() ruleengine.RuleSpec {
	return &ruleenginev1.RuleRequirements{
		EventTypes: R3005MaliciousFsMemoryInjectionRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
