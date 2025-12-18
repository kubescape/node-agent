package ruleadapters

import (
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
)

type RuleFailureCreatorInterface interface {
	CreateRuleFailure(rule typesv1.Rule, enrichedEvent *events.EnrichedEvent, objectCache objectcache.ObjectCache, message, uniqueID, apChecksum string, state map[string]any) types.RuleFailure
}

type EventMetadataSetter interface {
	SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent, state map[string]any)
}
