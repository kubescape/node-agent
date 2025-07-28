package rulefailurecreator

import (
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	types "github.com/kubescape/node-agent/pkg/rulemanager/types"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"
)

type RuleFailureCreatorInterface interface {
	CreateRuleFailure(rule typesv1.Rule, enrichedEvent *events.EnrichedEvent, objectCache objectcache.ObjectCache, message, uniqueID string) types.RuleFailure
	RegisterCreator(eventType utils.EventType, creator EventMetadataSetter)
}

type EventMetadataSetter interface {
	SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent)
}
