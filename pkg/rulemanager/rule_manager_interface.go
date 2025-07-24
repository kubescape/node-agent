package rulemanager

import (
	"github.com/kubescape/node-agent/pkg/utils"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"

	v1 "k8s.io/api/core/v1"
)

type RuleManagerClient interface {
	ContainerCallback(notif containercollection.PubSubEvent)
	RegisterPeekFunc(peek func(mntns uint64) ([]string, error))
	HasApplicableRuleBindings(namespace, name string) bool
	HasFinalApplicationProfile(pod *v1.Pod) bool
	IsContainerMonitored(k8sContainerID string) bool
	IsPodMonitored(namespace, pod string) bool
	EvaluatePolicyRulesForEvent(eventType utils.EventType, event utils.K8sEvent) []string
}
