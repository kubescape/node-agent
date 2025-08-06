package ruleadapters

import (
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
)

// EventRuleAdapter defines the interface for adapting events for rule processing.
// This interface supports both rule failure creation and provides event data
// in map format for rule evaluation.
type EventRuleAdapter interface {
	// SetFailureMetadata sets the failure-specific metadata for a rule failure based on the enriched event
	SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent)

	// ToMap converts the enriched event to a map representation that can be used for rule evaluation
	ToMap(enrichedEvent *events.EnrichedEvent) map[string]interface{}
}
