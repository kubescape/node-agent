package ruleengine

import (
	corev1 "k8s.io/api/core/v1"
)

var _ K8sCacher = (*K8sCacheMock)(nil)

type K8sCacheMock struct {
	podSpec            corev1.PodSpec
	apiServerIpAddress string
}

func (k *K8sCacheMock) GetPodSpec(podName, namespace, containerID string) (*corev1.PodSpec, error) {
	return &k.podSpec, nil
}
func (k *K8sCacheMock) GetApiServerIpAddress() (string, error) {
	return k.apiServerIpAddress, nil
}

type Rule interface {
	// Delete a rule instance.
	DeleteRule()

	// Rule Name.
	Name() string

	// Needed events for the rule.
	ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess, engineAccess EngineAccess) RuleFailure

	// Rule requirements.
	Requirements() RuleRequirements

	// Set rule parameters.
	SetParameters(parameters map[string]interface{})

	// Get rule parameters.
	GetParameters() map[string]interface{}
}

type RuleFailure interface {
	// Rule Name.
	Name() string
	// Priority.
	Priority() int
	// Error interface.
	Error() string
	// Fix suggestion.
	FixSuggestion() string
	// Generic event
	Event() tracing.GeneralEvent
}
