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
	R3006ID   = "R3006"
	R3006Name = "Suspicious Log Cleaning"
)

var accessLogFiles = []string{
	"/var/log/auth.log",
	"/var/log/secure",
	"/var/log/audit/audit.log",
	"/var/log/syslog",
	"/var/log/messages",
	"/var/log/kern.log",
}

var trustedLoggingImages = []string{
	"logrotate",
	"journald",
	"syslog-ng",
}

var R3006SuspiciousLogCleaningRuleDescriptor = ruleengine.RuleDescriptor{
	ID:          R3006ID,
	Name:        R3006Name,
	Description: "Detect clearing of critical access log files, typically done to erase evidence of adversary actions",
	Tags:        []string{"defense-evasion", "logging", "mitre_defense_evasion", "T1070", "NIST_800-53_AU-10"},
	Priority:    ruleenginev1.RulePriorityMed,
	Requirements: &ruleenginev1.RuleRequirements{
		EventTypes: []utils.EventType{utils.OpenEventType},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR3006SuspiciousLogCleaning()
	},
}

var _ ruleengine.RuleEvaluator = (*R3006SuspiciousLogCleaning)(nil)

type R3006SuspiciousLogCleaning struct {
	ruleenginev1.BaseRule
}

func CreateRuleR3006SuspiciousLogCleaning() *R3006SuspiciousLogCleaning {
	return &R3006SuspiciousLogCleaning{}
}

func (rule *R3006SuspiciousLogCleaning) Name() string {
	return R3006Name
}

func (rule *R3006SuspiciousLogCleaning) ID() string {
	return R3006ID
}

func (rule *R3006SuspiciousLogCleaning) SetParameters(parameters map[string]interface{}) {
	rule.BaseRule.SetParameters(parameters)
}

func (rule *R3006SuspiciousLogCleaning) DeleteRule() {
}

func (rule *R3006SuspiciousLogCleaning) ProcessEvent(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.OpenEventType {
		return nil
	}

	fullEvent, ok := event.(*events.OpenEvent)
	if !ok {
		return nil
	}

	openEvent := fullEvent.Event

	if !isAccessLogFile(openEvent.FullPath) {
		return nil
	}

	if !hasTargetFlags(openEvent.Flags, []string{"O_WRONLY", "O_RDWR", "O_TRUNC", "O_CREAT"}) {
		return nil
	}

	if isTrustedLoggingImage(openEvent.Runtime.ContainerImageName) {
		return nil
	}

	ruleFailure := ruleenginev1.GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName:   rule.Name(),
			InfectedPID: openEvent.Pid,
			Arguments: map[string]interface{}{
				"flags":   openEvent.Flags,
				"file":    openEvent.FullPath,
				"command": openEvent.Comm,
			},
			Severity: R3006SuspiciousLogCleaningRuleDescriptor.Priority,
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
			RuleDescription: fmt.Sprintf("Log file tampering detected: '%s' was truncated by process '%s' (PID: %d)",
				openEvent.FullPath,
				openEvent.Comm,
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

func (rule *R3006SuspiciousLogCleaning) Requirements() ruleengine.RuleSpec {
	return &ruleenginev1.RuleRequirements{
		EventTypes: R3006SuspiciousLogCleaningRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}

func isAccessLogFile(path string) bool {
	cleanPath := filepath.Clean(path)
	for _, logFile := range accessLogFiles {
		if cleanPath == logFile {
			return true
		}
	}
	return false
}

func isTrustedLoggingImage(imageName string) bool {
	for _, trustedImage := range trustedLoggingImages {
		if strings.Contains(strings.ToLower(imageName), trustedImage) {
			return true
		}
	}
	return false
}
