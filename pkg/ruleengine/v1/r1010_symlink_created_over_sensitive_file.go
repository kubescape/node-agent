package ruleengine

// This rule is disabled because we need to implement a special gadget for this rule since traceloop doesn't capture pointer values.

import (
	"fmt"
	"node-agent/pkg/objectcache"
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/utils"
	"strings"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"

	tracersyscalltype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/traceloop/types"
)

const (
	R1010ID   = "R1010"
	R1010Name = "Symlink Created Over Sensitive File"
)

var R1010SymlinkCreatedOverSensitiveFileRuleDescriptor = RuleDescriptor{
	ID:          R1010ID,
	Name:        R1010Name,
	Description: "Detecting symlink creation over sensitive files.",
	Tags:        []string{"files", "malicious"},
	Priority:    RulePriorityHigh,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.SyscallEventType,
		},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1010SymlinkCreatedOverSensitiveFile()
	},
}
var _ ruleengine.RuleEvaluator = (*R1010SymlinkCreatedOverSensitiveFile)(nil)

type R1010SymlinkCreatedOverSensitiveFile struct {
	BaseRule
	additionalPaths []string
}

func CreateRuleR1010SymlinkCreatedOverSensitiveFile() *R1010SymlinkCreatedOverSensitiveFile {
	return &R1010SymlinkCreatedOverSensitiveFile{
		additionalPaths: SensitiveFiles,
	}
}

func (rule *R1010SymlinkCreatedOverSensitiveFile) SetParameters(parameters map[string]interface{}) {
	rule.BaseRule.SetParameters(parameters)

	additionalPathsInterface := rule.GetParameters()["additionalPaths"]
	if additionalPathsInterface == nil {
		return
	}

	additionalPaths, ok := interfaceToStringSlice(additionalPathsInterface)
	if ok {
		for _, path := range additionalPaths {
			rule.additionalPaths = append(rule.additionalPaths, fmt.Sprintf("%v", path))
		}
	} else {
		logger.L().Warning("failed to convert additionalPaths to []string", helpers.String("ruleID", rule.ID()))
	}
}

func (rule *R1010SymlinkCreatedOverSensitiveFile) Name() string {
	return R1010Name
}

func (rule *R1010SymlinkCreatedOverSensitiveFile) ID() string {
	return R1010ID
}

func (rule *R1010SymlinkCreatedOverSensitiveFile) DeleteRule() {
}

func (rule *R1010SymlinkCreatedOverSensitiveFile) ProcessEvent(eventType utils.EventType, event interface{}, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.SyscallEventType {
		return nil
	}

	syscallEvent, ok := event.(*tracersyscalltype.Event)
	if !ok {
		return nil
	}

	if syscallEvent.Syscall == "symlink" || syscallEvent.Syscall == "symlinkat" {
		if syscallEvent.Parameters[0].Name == "target" || syscallEvent.Parameters[0].Name == "oldname" {
			value := syscallEvent.Parameters[0].Value
			if syscallEvent.Parameters[0].Content != nil {
				value = *syscallEvent.Parameters[0].Content
			}
			for _, path := range rule.additionalPaths {
				if strings.HasPrefix(value, path) {
					return &GenericRuleFailure{
						BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
							AlertName:      rule.Name(),
							InfectedPID:    syscallEvent.Pid,
							FixSuggestions: "If this is a legitimate action, please consider removing this workload from the binding of this rule.",
							Severity:       R1010SymlinkCreatedOverSensitiveFileRuleDescriptor.Priority,
						},
						RuntimeProcessDetails: apitypes.ProcessTree{
							ProcessTree: apitypes.Process{
								Comm: syscallEvent.Comm,
								PID:  syscallEvent.Pid,
							},
							ContainerID: syscallEvent.Runtime.ContainerID,
						},
						TriggerEvent: syscallEvent.Event,
						RuleAlert: apitypes.RuleAlert{
							RuleID:          rule.ID(),
							RuleDescription: fmt.Sprintf("Symlink created over sensitive file: %s in: %s", value, syscallEvent.GetContainer()),
						},
						RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
							PodName: syscallEvent.GetPod(),
						},
					}
				}
			}
		}
	}

	return nil
}

func (rule *R1010SymlinkCreatedOverSensitiveFile) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1010SymlinkCreatedOverSensitiveFileRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}