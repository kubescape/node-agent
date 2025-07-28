package ruleswatcher

import (
	"context"

	"github.com/kubescape/node-agent/pkg/watcher"
)

type RulesWatcher interface {
	watcher.Adaptor
	InitialSync(ctx context.Context) error
}

type RulesWatcherCallback = func()
