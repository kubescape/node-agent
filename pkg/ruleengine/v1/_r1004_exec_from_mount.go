package ruleengine

import (
	"fmt"
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/utils"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/kubescape/kapprofiler/pkg/tracing"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

const (
	R1004ID                    = "R1004"
	R1004ExecFromMountRuleName = "Exec from mount"
)

var R1004ExecFromMountRuleDescriptor = RuleDescriptor{
	ID:          R1004ID,
	Name:        R1004ExecFromMountRuleName,
	Description: "Detecting exec calls from mounted paths.",
	Tags:        []string{"exec", "mount"},
	Priority:    RulePriorityMed,
	Requirements: &RuleRequirements{
		EventTypes:             []utils.EventType{utils.ExecveEventType},
		NeedApplicationProfile: false,
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1004ExecFromMount()
	},
}

type R1004ExecFromMount struct {
	BaseRule
	// Map of container ID to mount paths
	mutex                   sync.RWMutex
	containerIdToMountPaths map[string][]string
}

type R1004ExecFromMountFailure struct {
	RuleName         string
	RulePriority     int
	Err              string
	FixSuggestionMsg string
	FailureEvent     *utils.GeneralEvent
}

func (rule *R1004ExecFromMount) Name() string {
	return R1004ExecFromMountRuleName
}

func CreateRuleR1004ExecFromMount() *R1004ExecFromMount {
	return &R1004ExecFromMount{
		containerIdToMountPaths: map[string][]string{},
	}
}

func (rule *R1004ExecFromMount) DeleteRule() {
}

func (rule *R1004ExecFromMount) ProcessEvent(eventType utils.EventType, event interface{}, ap *v1beta1.ApplicationProfile, k8sProvider ruleengine.K8sObjectProvider) ruleengine.RuleFailure {
	if eventType != utils.ExecveEventType {
		return nil
	}

	execEvent, ok := event.(*tracing.ExecveEvent)
	if !ok {
		return nil
	}

	rule.mutex.RLock()
	mounts, ok := rule.containerIdToMountPaths[execEvent.ContainerID]
	rule.mutex.RUnlock()
	if !ok {
		err := rule.setMountPaths(execEvent.PodName, execEvent.Namespace, execEvent.ContainerID, execEvent.ContainerName, engineAccess)
		if err != nil {
			log.Printf("Failed to set mount paths: %v", err)
			return nil
		}
		rule.mutex.RLock()
		mounts = rule.containerIdToMountPaths[execEvent.ContainerID]
		rule.mutex.RUnlock()
	}

	for _, mount := range mounts {
		contained := rule.isPathContained(execEvent.PathName, mount)
		if contained {
			log.Debugf("Path %s is mounted in pod %s/%s", execEvent.PathName, execEvent.Namespace, execEvent.PodName)
			return &R1004ExecFromMountFailure{
				RuleName:         rule.Name(),
				Err:              "Exec from mount",
				FailureEvent:     utils.ExecToGeneralEvent(execEvent),
				FixSuggestionMsg: "If this is a legitimate action, please consider removing this workload from the binding of this rule",
				RulePriority:     R1004ExecFromMountRuleDescriptor.Priority,
			}
		}
	}

	return nil

}

func (rule *R1004ExecFromMount) setMountPaths(podName string, namespace string, containerID string, containerName string, k8sProvider ruleengine.K8sObjectProvider) error {
	podSpec, err := k8sProvider.GetPodSpec(namespace, podName)
	if err != nil {
		return fmt.Errorf("failed to get pod spec: %v", err)
	}

	mountPaths := []string{}
	for _, container := range podSpec.Containers {
		if container.Name == containerName {
			for _, volumeMount := range container.VolumeMounts {
				mountPaths = append(mountPaths, volumeMount.MountPath)
			}
		}
	}

	rule.mutex.Lock()
	defer rule.mutex.Unlock()
	rule.containerIdToMountPaths[containerID] = mountPaths

	return nil
}

func (rule *R1004ExecFromMount) isPathContained(targetpath, basepath string) bool {
	return strings.HasPrefix(targetpath, basepath)
}

func (rule *R1004ExecFromMount) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes:             []utils.EventType{utils.ExecveEventType},
		NeedApplicationProfile: false,
	}
}

func (rule *R1004ExecFromMountFailure) Name() string {
	return rule.RuleName
}

func (rule *R1004ExecFromMountFailure) Error() string {
	return rule.Err
}

func (rule *R1004ExecFromMountFailure) Event() *utils.GeneralEvent {
	return rule.FailureEvent
}

func (rule *R1004ExecFromMountFailure) Priority() int {
	return rule.RulePriority
}

func (rule *R1004ExecFromMountFailure) FixSuggestion() string {
	return rule.FixSuggestionMsg
}
