package ruleengine

import (
	"fmt"
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/ruleengine/objectcache"
	"node-agent/pkg/utils"
	"strings"

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
		EventTypes:             []utils.EventType{utils.ExecveEventType},
		NeedApplicationProfile: false,
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

	// /proc/self/fd/<n> is classic way to hide malicious execs
	// (see ezuri packer for example)
	// Here it would be even more interesting to check if the fd
	// is memory mapped file

	// The assumption here is that the event path is absolute!
	p := getExecPathFromEvent(execEvent)
	for _, maliciousExecPathPrefix := range maliciousExecPathPrefixes {
		// if the exec path or the current dir is from a malicious source
		if strings.HasPrefix(p, maliciousExecPathPrefix) || strings.HasPrefix(execEvent.Cwd, maliciousExecPathPrefix) {
			return &GenericRuleFailure{
				RuleName:         rule.Name(),
				Err:              fmt.Sprintf("exec call \"%s\" is from a malicious source \"%s\"", p, maliciousExecPathPrefix),
				FixSuggestionMsg: "If this is a legitimate action, please add consider removing this workload from the binding of this rule.",
				FailureEvent:     utils.ExecToGeneralEvent(execEvent),
				RulePriority:     R1000ExecFromMaliciousSourceDescriptor.Priority,
			}
		}
	}

	return nil
}

func (rule *R1000ExecFromMaliciousSource) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes:             []utils.EventType{utils.ExecveEventType},
		NeedApplicationProfile: false,
	}
}
