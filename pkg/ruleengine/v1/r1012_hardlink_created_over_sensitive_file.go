package ruleengine

import (
	"fmt"
	"node-agent/pkg/objectcache"
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/utils"
	"strings"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"

	tracerhardlinktype "node-agent/pkg/ebpf/gadgets/hardlink/types"
)

const (
	R1012ID   = "R1012"
	R1012Name = "Hardlink Created Over Sensitive File"
)

var R1012HardlinkCreatedOverSensitiveFileRuleDescriptor = RuleDescriptor{
	ID:          R1012ID,
	Name:        R1012Name,
	Description: "Detecting hardlink creation over sensitive files.",
	Tags:        []string{"files", "malicious"},
	Priority:    RulePriorityHigh,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.HardlinkEventType,
		},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1012HardlinkCreatedOverSensitiveFile()
	},
}
var _ ruleengine.RuleEvaluator = (*R1012HardlinkCreatedOverSensitiveFile)(nil)

type R1012HardlinkCreatedOverSensitiveFile struct {
	BaseRule
	additionalPaths []string
}

func CreateRuleR1012HardlinkCreatedOverSensitiveFile() *R1012HardlinkCreatedOverSensitiveFile {
	return &R1012HardlinkCreatedOverSensitiveFile{
		additionalPaths: SensitiveFiles,
	}
}

func (rule *R1012HardlinkCreatedOverSensitiveFile) SetParameters(parameters map[string]interface{}) {
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

func (rule *R1012HardlinkCreatedOverSensitiveFile) Name() string {
	return R1012Name
}

func (rule *R1012HardlinkCreatedOverSensitiveFile) ID() string {
	return R1012ID
}

func (rule *R1012HardlinkCreatedOverSensitiveFile) DeleteRule() {
}

func (rule *R1012HardlinkCreatedOverSensitiveFile) ProcessEvent(eventType utils.EventType, event interface{}, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.HardlinkEventType {
		return nil
	}

	hardlinkEvent, ok := event.(*tracerhardlinktype.Event)
	if !ok {
		return nil
	}

	for _, path := range rule.additionalPaths {
		if strings.HasPrefix(hardlinkEvent.OldPath, path) {
			return &GenericRuleFailure{
				BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
					AlertName:      rule.Name(),
					InfectedPID:    hardlinkEvent.Pid,
					FixSuggestions: "If this is a legitimate action, please consider removing this workload from the binding of this rule.",
					Severity:       R1012HardlinkCreatedOverSensitiveFileRuleDescriptor.Priority,
				},
				RuntimeProcessDetails: apitypes.ProcessTree{
					ProcessTree: apitypes.Process{
						Comm:       hardlinkEvent.Comm,
						PPID:       hardlinkEvent.PPid,
						PID:        hardlinkEvent.Pid,
						UpperLayer: &hardlinkEvent.UpperLayer,
						Uid:        &hardlinkEvent.Uid,
						Gid:        &hardlinkEvent.Gid,
					},
					ContainerID: hardlinkEvent.Runtime.ContainerID,
				},
				TriggerEvent: hardlinkEvent.Event,
				RuleAlert: apitypes.RuleAlert{
					RuleDescription: fmt.Sprintf("Hardlink created over sensitive file: %s - %s in: %s", hardlinkEvent.OldPath, hardlinkEvent.NewPath, hardlinkEvent.GetContainer()),
				},
				RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
					PodName: hardlinkEvent.GetPod(),
				},
				RuleID: rule.ID(),
			}
		}
	}

	return nil
}

func (rule *R1012HardlinkCreatedOverSensitiveFile) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1012HardlinkCreatedOverSensitiveFileRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
