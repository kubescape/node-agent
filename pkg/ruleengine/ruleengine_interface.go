package ruleengine

import (
	"node-agent/pkg/utils"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"

	corev1 "k8s.io/api/core/v1"
	// "node-agent/pkg/ruleengine"
)

type K8sCacher interface {
	GetPodSpec(podName, namespace, containerID string) (*corev1.PodSpec, error)
	GetApiServerIpAddress() (string, error)
}

type RuleEvaluator interface {

	// Rule Name
	Name() string

	// Rule processing
	ProcessEvent(eventType utils.EventType, event interface{}, ap *v1beta1.ApplicationProfile, k8sCacher K8sCacher) RuleFailure

	// Rule requirements
	Requirements() RuleSpec

	// Set rule parameters
	SetParameters(parameters map[string]interface{})

	// Get rule parameters
	GetParameters() map[string]interface{}
}

// RuleSpec is an interface for rule requirements
type RuleSpec interface {
	// Event types required for the rule
	RequiredEventTypes() []utils.EventType

	// Some rules need an application profile
	IsApplicationProfileRequired() bool
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
	Event() *utils.GeneralEvent
}
