package callbacks

import (
	"github.com/kubescape/node-agent/pkg/applicationprofilemanager"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/rulemanager"
)

// EventProcessor defines the interface for processing different event types
type EventProcessor interface {
	Process(event interface{})
}

// GenericWorkerCallback is the generic callback function for all worker pools
func GenericWorkerCallback(processor EventProcessor) func(interface{}) {
	return func(i interface{}) {
		processor.Process(i)
	}
}

// BaseEventProcessor provides common processing logic for all event types
type BaseEventProcessor struct {
	metrics                   metricsmanager.MetricsManager
	applicationProfileManager applicationprofilemanager.ApplicationProfileManagerClient
	ruleManager               rulemanager.RuleManagerClient
	// Add other common dependencies here
}

/*
func (b *BaseEventProcessor) commonProcessing(eventType utils.EventType, k8sContainerID string) {
	b.metrics.ReportEvent(eventType)
	b.ruleManager.ReportEvent(eventType, event)
}
*/
