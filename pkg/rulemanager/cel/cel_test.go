//go:build linux

package cel

import (
	"testing"

	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestCEL(t *testing.T) *CEL {
	t.Helper()
	objCache := objectcachev1.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}
	c, err := NewCEL(&objCache, config.Config{})
	require.NoError(t, err)
	return c
}

func TestConstantFoldingExpressions(t *testing.T) {
	c := newTestCEL(t)

	tests := []struct {
		name       string
		expression string
		event      utils.K8sEvent
		want       bool
	}{
		{
			name:       "uint cast folds correctly - match",
			expression: "event.cmd == uint(5)",
			event: &utils.StructEvent{
				EventType: utils.ExecveEventType,
				Cmd:       5,
			},
			want: true,
		},
		{
			name:       "uint cast folds correctly - no match",
			expression: "event.cmd == uint(5)",
			event: &utils.StructEvent{
				EventType: utils.ExecveEventType,
				Cmd:       99,
			},
			want: false,
		},
		{
			name:       "uint in list literal - first element match",
			expression: "event.cmd in [uint(22), uint(2022)]",
			event: &utils.StructEvent{
				EventType: utils.ExecveEventType,
				Cmd:       22,
			},
			want: true,
		},
		{
			name:       "uint in list literal - second element match",
			expression: "event.cmd in [uint(22), uint(2022)]",
			event: &utils.StructEvent{
				EventType: utils.ExecveEventType,
				Cmd:       2022,
			},
			want: true,
		},
		{
			name:       "uint in list literal - no match",
			expression: "event.cmd in [uint(22), uint(2022)]",
			event: &utils.StructEvent{
				EventType: utils.ExecveEventType,
				Cmd:       7,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := c.CreateEvalContext(tt.event)
			defer ctx.Release()
			got, err := c.EvaluateRuleWithContext(ctx, []typesv1.RuleExpression{{Expression: tt.expression}})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
