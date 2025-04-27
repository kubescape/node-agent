package exporters

import (
	"context"
	"time"

	"github.com/kubescape/node-agent/pkg/ruleengine"
	"go.vallahaye.net/batcher"
)

type RuleBatcher struct {
	b *batcher.Batcher[ruleengine.RuleFailure, any]
}

func NewRuleBatcher(batchSize int, maxWait time.Duration, sendFunc func([]ruleengine.RuleFailure)) *RuleBatcher {
	commitFn := func(ctx context.Context, ops batcher.Operations[ruleengine.RuleFailure, any]) {
		batch := make([]ruleengine.RuleFailure, 0, len(ops))
		for _, op := range ops {
			batch = append(batch, op.Value)
		}
		sendFunc(batch)
	}
	b := batcher.New(commitFn,
		batcher.WithMaxSize[ruleengine.RuleFailure, any](batchSize),
		batcher.WithTimeout[ruleengine.RuleFailure, any](maxWait),
	)
	return &RuleBatcher{b: b}
}

func (rb *RuleBatcher) Start(ctx context.Context) {
	go rb.b.Batch(ctx)
}

func (rb *RuleBatcher) Add(ctx context.Context, alert ruleengine.RuleFailure) error {
	_, err := rb.b.Send(ctx, alert)
	return err
}
