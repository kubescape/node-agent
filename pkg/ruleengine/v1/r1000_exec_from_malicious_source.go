package ruleengine

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
)

const (
	R1000ID   = "R1000"
	R1000Name = "Exec from malicious source"
)

var R1000ExecFromMaliciousSourceDescriptor = ruleengine.RuleDescriptor{
	ID:          R1000ID,
	Name:        R1000Name,
	Description: "Detecting exec calls that are from malicious source like: /dev/shm, /proc/self",
	Priority:    RulePriorityMed,
	Tags:        []string{"exec", "signature"},
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{utils.ExecveEventType},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1000ExecFromMaliciousSource()
	},
}
var _ ruleengine.RuleEvaluator = (*R1000ExecFromMaliciousSource)(nil)

type R1000ExecFromMaliciousSource struct {
	BaseRule
}

func CreateRuleR1000ExecFromMaliciousSource() *R1000ExecFromMaliciousSource {
	return &R1000ExecFromMaliciousSource{}
}

func (rule *R1000ExecFromMaliciousSource) Name() string {
	return R1000Name
}

func (rule *R1000ExecFromMaliciousSource) ID() string {
	return R1000ID
}

var whitelistedProcessesForMaliciousSource = []string{
	"systemd",
	"docker",
	"containerd",
	"snap-confine",
	"nginx",
	"apache2",
	"bash",
	"dash",
	"sh",
	"perl",
	"supervisord",
}

func (rule *R1000ExecFromMaliciousSource) ProcessEvent(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.ExecveEventType {
		return nil
	}

	execEvent, ok := event.(*events.ExecEvent)
	if !ok {
		return nil
	}

	var maliciousExecPathPrefixes = []string{
		"/dev/shm",
		"/proc/self/fd",
	}

	if objCache == nil {
		// Running without object cache, to avoid false positives check if the process name is legitimate
		for _, processName := range whitelistedProcessesForMaliciousSource {
			if processName == execEvent.Comm {
				return nil
			}
		}
	}

	execPath := GetExecFullPathFromEvent(execEvent)
	execPathDir := filepath.Dir(execPath)
	for _, maliciousExecPathPrefix := range maliciousExecPathPrefixes {
		// if the exec path or the current dir is from a malicious source
		if strings.HasPrefix(execPathDir, maliciousExecPathPrefix) || strings.HasPrefix(execEvent.Cwd, maliciousExecPathPrefix) || strings.HasPrefix(execEvent.ExePath, maliciousExecPathPrefix) {
			upperLayer := execEvent.UpperLayer || execEvent.PupperLayer

			ruleFailure := GenericRuleFailure{
				BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
					AlertName:   rule.Name(),
					InfectedPID: execEvent.Pid,
					Arguments: map[string]interface{}{
						"hardlink": execEvent.ExePath,
					},
					Severity: R1000ExecFromMaliciousSourceDescriptor.Priority,
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
						Path:       execPath,
						Cmdline:    fmt.Sprintf("%s %s", GetExecPathFromEvent(execEvent), strings.Join(utils.GetExecArgsFromEvent(&execEvent.Event), " ")),
					},
					ContainerID: execEvent.Runtime.ContainerID,
				},
				TriggerEvent: execEvent.Event.Event,
				RuleAlert: apitypes.RuleAlert{
					RuleDescription: fmt.Sprintf("Execution from malicious source: %s in: %s", execPathDir, execEvent.GetContainer()),
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
	}

	return nil
}

func (rule *R1000ExecFromMaliciousSource) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1000ExecFromMaliciousSourceDescriptor.Requirements.RequiredEventTypes(),
	}
}
