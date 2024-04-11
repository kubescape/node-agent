package ruleengine

import (
	"fmt"
	"node-agent/pkg/objectcache"
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/utils"
	"path/filepath"
	"strings"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
)

const (
	R1000ID   = "R1000"
	R1000Name = "Exec from malicious source"
)

var R1000ExecFromMaliciousSourceDescriptor = RuleDescriptor{
	ID:          R1000ID,
	Name:        R1000Name,
	Description: "Detecting exec calls that are from malicious source like: /dev/shm, /run, /var/run, /proc/self",
	Priority:    RulePriorityCritical,
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

func (rule *R1000ExecFromMaliciousSource) ProcessEvent(eventType utils.EventType, event interface{}, _ objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.ExecveEventType {
		return nil
	}

	execEvent, ok := event.(*tracerexectype.Event)
	if !ok {
		return nil
	}

	var maliciousExecPathPrefixes = []string{
		"/dev/shm",
		"/run",
		"/var/run",
		"/proc/self",
	}

	// The assumption here is that the event path is absolute!
	execPath := getExecPathFromEvent(execEvent)
	if strings.HasPrefix(execPath, "./") || strings.HasPrefix(execPath, "../") {
		execPath = filepath.Join(execEvent.Cwd, execPath)
	} else if !strings.HasPrefix(execPath, "/") {
		execPath = "/" + execPath
	}
	execPath = filepath.Dir(execPath)
	for _, maliciousExecPathPrefix := range maliciousExecPathPrefixes {
		// if the exec path or the current dir is from a malicious source
		if strings.HasPrefix(execPath, maliciousExecPathPrefix) || strings.HasPrefix(execEvent.Cwd, maliciousExecPathPrefix) || strings.HasPrefix(execEvent.ExePath, maliciousExecPathPrefix) {
			isPartOfImage := !execEvent.UpperLayer
			ruleFailure := GenericRuleFailure{
				BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
					AlertName: rule.Name(),
					Arguments: map[string]interface{}{
						"hardlink": execEvent.ExePath,
					},
					FixSuggestions: "If this is a legitimate action, please add consider removing this workload from the binding of this rule.",
					Severity:       R1000ExecFromMaliciousSourceDescriptor.Priority,
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
					RuleDescription: fmt.Sprintf("Execution from malicious source: %s in: %s", execPath, execEvent.GetContainer()),
				},
				RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{},
			}

			enrichRuleFailure(execEvent.Event, execEvent.Pid, &ruleFailure)

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
