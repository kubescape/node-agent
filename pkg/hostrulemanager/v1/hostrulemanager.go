package hostrulemanager

import (
	"context"

	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/hostrulemanager"
	hostrules "github.com/kubescape/node-agent/pkg/hostrules/v1"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	ruleenginev1 "github.com/kubescape/node-agent/pkg/ruleengine/v1"
	"github.com/kubescape/node-agent/pkg/utils"
)

type RuleManager struct {
	ctx         context.Context
	exporter    exporters.Exporter
	objectCache objectcache.ObjectCache
	ruleCreator *ruleenginev1.RuleCreatorImpl
}

var _ hostrulemanager.HostRuleManagerClient = &RuleManager{}

func NewRuleManager(ctx context.Context, exporter exporters.Exporter, objectCache objectcache.ObjectCache) *RuleManager {
	return &RuleManager{
		ctx:         ctx,
		exporter:    exporter,
		objectCache: objectCache,
		ruleCreator: hostrules.NewRuleCreator(),
	}
}

func (r *RuleManager) ReportEvent(eventType utils.EventType, event utils.K8sEvent) {
	r.processEvent(eventType, event, r.ruleCreator.CreateRulesByEventType(eventType))
}

func (r *RuleManager) processEvent(eventType utils.EventType, event utils.K8sEvent, rules []ruleengine.RuleEvaluator) {
	for _, rule := range rules {
		if rule == nil {
			continue
		}

		if !isEventRelevant(rule.Requirements(), eventType) {
			continue
		}

		res := rule.ProcessEvent(eventType, event, r.objectCache)
		if res != nil {
			r.exporter.SendRuleAlert(res) // TODO: SEND IT TO DIFFERENT FUNCTION.
		}
	}
}

// Checks if the event type is relevant to the rule.
func isEventRelevant(ruleSpec ruleengine.RuleSpec, eventType utils.EventType) bool {
	for _, i := range ruleSpec.RequiredEventTypes() {
		if i == eventType {
			return true
		}
	}
	return false
}
