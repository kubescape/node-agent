package ruleswatcher

import (
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
)

type RulesWatcherImpl struct {
	callback func(rules []typesv1.Rule)
}

func NewRulesWatcher(callback func(rules []typesv1.Rule)) *RulesWatcherImpl {
	return &RulesWatcherImpl{
		callback: callback,
	}
}
