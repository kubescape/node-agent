package ruleswatcher

import (
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
)

type RulesWatcher interface {
	Start()
	Stop()
	SetCallback(callback func(rules []typesv1.Rule))
}
