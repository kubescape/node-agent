package ruleadapters

import (
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
)

type EventRuleAdapter interface {
	SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent, state map[string]any)
}
