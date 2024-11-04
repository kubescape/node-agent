package ruleengine

import (
	"errors"
	"fmt"
	"strings"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"

	tracersymlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/symlink/types"
)

const (
	R1010ID   = "R1010"
	R1010Name = "Symlink Created Over Sensitive File"
)

var R1010SymlinkCreatedOverSensitiveFileRuleDescriptor = ruleengine.RuleDescriptor{
	ID:          R1010ID,
	Name:        R1010Name,
	Description: "Detecting symlink creation over sensitive files.",
	Tags:        []string{"files", "malicious"},
	Priority:    RulePriorityHigh,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.SymlinkEventType,
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

func (rule *R1010SymlinkCreatedOverSensitiveFile) ProcessEvent(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.SymlinkEventType {
		return nil
	}

	symlinkEvent, ok := event.(*tracersymlinktype.Event)
	if !ok {
		return nil
	}

	if allowed, err := isAllowed(&symlinkEvent.Event, objCache, symlinkEvent.Comm, R1012ID); err != nil {
		logger.L().Error("failed to check if symlink is allowed", helpers.String("ruleID", rule.ID()), helpers.String("error", err.Error()))
	} else if allowed {
		return nil
	}

	for _, path := range rule.additionalPaths {
		if strings.HasPrefix(symlinkEvent.OldPath, path) {
			return &GenericRuleFailure{
				BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
					AlertName: rule.Name(),
					Arguments: map[string]interface{}{
						"oldPath": symlinkEvent.OldPath,
						"newPath": symlinkEvent.NewPath,
					},
					InfectedPID:    symlinkEvent.Pid,
					FixSuggestions: "If this is a legitimate action, please consider removing this workload from the binding of this rule.",
					Severity:       R1010SymlinkCreatedOverSensitiveFileRuleDescriptor.Priority,
				},
				RuntimeProcessDetails: apitypes.ProcessTree{
					ProcessTree: apitypes.Process{
						Comm:       symlinkEvent.Comm,
						PPID:       symlinkEvent.PPid,
						PID:        symlinkEvent.Pid,
						UpperLayer: &symlinkEvent.UpperLayer,
						Uid:        &symlinkEvent.Uid,
						Gid:        &symlinkEvent.Gid,
						Hardlink:   symlinkEvent.ExePath,
						Path:       symlinkEvent.ExePath,
					},
					ContainerID: symlinkEvent.Runtime.ContainerID,
				},
				TriggerEvent: symlinkEvent.Event,
				RuleAlert: apitypes.RuleAlert{
					RuleDescription: fmt.Sprintf("Symlink created over sensitive file: %s - %s in: %s", symlinkEvent.OldPath, symlinkEvent.NewPath, symlinkEvent.GetContainer()),
				},
				RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
					PodName:   symlinkEvent.GetPod(),
					PodLabels: symlinkEvent.K8s.PodLabels,
				},
				RuleID: rule.ID(),
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

func isSymLinkAllowed(symlinkEvent *tracersymlinktype.Event, objCache objectcache.ObjectCache) (bool, error) {
	ap := objCache.ApplicationProfileCache().GetApplicationProfile(symlinkEvent.Runtime.ContainerID)
	if ap == nil {
		return true, errors.New("application profile not found")
	}

	appProfileExecList, err := getContainerFromApplicationProfile(ap, symlinkEvent.GetContainer())
	if err != nil {
		return true, err
	}

	for _, exec := range appProfileExecList.Execs {
		if exec.Path == symlinkEvent.Comm {
			return true, nil
		}
	}

	return false, nil
}
