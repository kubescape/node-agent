package rulefailurecreator

import (
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

type RuleFailureCreatorInterface interface {
	CreateRuleFailure(rule types.Rule, enrichedEvent *events.EnrichedEvent, objectCache objectcache.ObjectCache, message, uniqueID string) ruleengine.RuleFailure
	RegisterCreator(eventType utils.EventType, creator EventMetadataSetter)
}

type EventMetadataSetter interface {
	SetFailureMetadata(failure ruleengine.RuleFailure, enrichedEvent *events.EnrichedEvent)
}
