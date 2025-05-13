package ruleengine

import (
	"errors"
	"fmt"
	"strings"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
)

const (
	R1004ID   = "R1004"
	R1004Name = "Exec from mount"
)

var R1004ExecFromMountRuleDescriptor = ruleengine.RuleDescriptor{
	ID:          R1004ID,
	Name:        R1004Name,
	Description: "Detecting exec calls from mounted paths.",
	Tags:        []string{"exec", "mount"},
	Priority:    RulePriorityMed,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{utils.ExecveEventType},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1004ExecFromMount()
	},
}

type R1004ExecFromMount struct {
	BaseRule
}

func CreateRuleR1004ExecFromMount() *R1004ExecFromMount {
	return &R1004ExecFromMount{}
}
func (rule *R1004ExecFromMount) Name() string {
	return R1004Name
}

func (rule *R1004ExecFromMount) ID() string {
	return R1004ID
}

func (rule *R1004ExecFromMount) DeleteRule() {
}

func (rule *R1004ExecFromMount) ProcessEvent(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.ExecveEventType {
		return nil
	}

	execEvent, ok := event.(*events.ExecEvent)
	if !ok {
		return nil
	}

	// Check if the event is expected, if so return nil
	// No application profile also returns nil
	var profileMetadata *apitypes.ProfileMetadata
	whiteListed, err := IsExecEventInProfile(execEvent, objCache, false)
	if whiteListed {
		return nil
	} else if err != nil && !errors.Is(err, ProfileNotFound) {
		ap := objCache.ApplicationProfileCache().GetApplicationProfile(execEvent.Runtime.ContainerID)
		if ap != nil {
			profileMetadata = &apitypes.ProfileMetadata{
				Status:             ap.GetAnnotations()[helpersv1.StatusMetadataKey],
				Completion:         ap.GetAnnotations()[helpersv1.CompletionMetadataKey],
				Name:               ap.Name,
				Type:               apitypes.ApplicationProfile,
				IsProfileDependent: true,
			}
		}
	}

	mounts, err := GetContainerMountPaths(execEvent.GetNamespace(), execEvent.GetPod(), execEvent.GetContainer(), objCache.K8sObjectCache())
	if err != nil {
		return nil
	}

	for _, mount := range mounts {
		fullPath := GetExecFullPathFromEvent(execEvent)
		if rule.isPathContained(fullPath, mount) || rule.isPathContained(execEvent.ExePath, mount) {
			upperLayer := execEvent.UpperLayer || execEvent.PupperLayer
			ruleFailure := GenericRuleFailure{
				BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
					UniqueID:    HashStringToMD5(fmt.Sprintf("%s%s%s", execEvent.Comm, execEvent.ExePath, execEvent.Pcomm)),
					AlertName:   rule.Name(),
					InfectedPID: execEvent.Pid,
					Arguments: map[string]interface{}{
						"exec": execEvent.ExePath,
						"args": execEvent.Args,
					},
					Severity:        R1004ExecFromMountRuleDescriptor.Priority,
					ProfileMetadata: profileMetadata,
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
						Path:       fullPath,
						Cmdline:    fmt.Sprintf("%s %s", GetExecPathFromEvent(execEvent), strings.Join(utils.GetExecArgsFromEvent(&execEvent.Event), " ")),
					},
					ContainerID: execEvent.Runtime.ContainerID,
				},
				TriggerEvent: execEvent.Event.Event,
				RuleAlert: apitypes.RuleAlert{
					RuleDescription: fmt.Sprintf("Process (%s) was executed from a mounted path (%s)", fullPath, mount),
				},
				RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
					PodName:   execEvent.GetPod(),
					PodLabels: execEvent.K8s.PodLabels,
				},
				RuleID: R1004ID,
				Extra:  execEvent.GetExtra(),
			}

			return &ruleFailure
		}
	}

	return nil
}

func (rule *R1004ExecFromMount) isPathContained(targetpath, basepath string) bool {
	return strings.HasPrefix(targetpath, basepath)
}

func (rule *R1004ExecFromMount) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1004ExecFromMountRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
