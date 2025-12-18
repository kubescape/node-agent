package rulemanager

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/utils"
	corev1 "k8s.io/api/core/v1"
)

type RuleManagerMock struct {
}

var _ RuleManagerClient = (*RuleManagerMock)(nil)
var _ containerwatcher.EnrichedEventReceiver = (*RuleManagerMock)(nil)

func CreateRuleManagerMock() RuleManagerClient {
	return &RuleManagerMock{}
}

func (r RuleManagerMock) ContainerCallback(notif containercollection.PubSubEvent) {
	// noop
}

func (r RuleManagerMock) HasApplicableRuleBindings(namespace, name string) bool {
	return false
}

func (r RuleManagerMock) HasFinalApplicationProfile(pod *corev1.Pod) bool {
	return false
}

func (r RuleManagerMock) IsContainerMonitored(k8sContainerID string) bool {
	return false
}

func (r RuleManagerMock) IsPodMonitored(namespace, pod string) bool {
	return false
}

func (r RuleManagerMock) EvaluatePolicyRulesForEvent(eventType utils.EventType, event utils.K8sEvent) []string {
	return []string{}
}

func (r RuleManagerMock) ReportEnrichedEvent(enrichedEvent *events.EnrichedEvent) {
	// noop
}
