package ruleadapters

import (
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	types "github.com/kubescape/node-agent/pkg/rulemanager/types"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
)

type RuleFailureCreatorInterface interface {
	CreateRuleFailure(rule typesv1.Rule, enrichedEvent *events.EnrichedEvent, objectCache objectcache.ObjectCache, message, uniqueID string) types.RuleFailure
}

// EventMetadataSetter is deprecated, use EventRuleAdapter instead
type EventMetadataSetter interface {
	SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent)
}
