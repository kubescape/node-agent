package rulecreator_test

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/rulemanager/rulecreator"

	"github.com/kubescape/node-agent/pkg/contextdetection"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/stretchr/testify/require"
)

func TestCreateRulesObservesPreviouslyUnfilteredState(t *testing.T) {
	for _, accessor := range []string{"all", "context"} {
		t.Run(accessor, func(t *testing.T) {
			state := map[string]any{"custom_state": "value"}
			creator := &rulecreator.RuleCreatorImpl{Rules: []typesv1.Rule{{ID: "rule", State: state}}}
			get := creator.CreateAllRules
			if accessor == "context" {
				get = func() []typesv1.Rule {
					return creator.CreateRulesForContext(contextdetection.Kubernetes)
				}
			}
			rules := get()
			require.Len(t, rules, 1)
			require.Nil(t, rules[0].Prefilter)
			// Results shallow-share state; serial mutations must remain visible
			// until a nonnil prefilter is initialized, as before this optimization.
			rules[0].State["ports"] = []uint16{443}
			rules = get()
			require.NotNil(t, rules[0].Prefilter)
			require.Equal(t, []uint16{443}, rules[0].Prefilter.Ports)
			creator.UpdateRule(typesv1.Rule{ID: "rule", State: map[string]any{"ports": []uint16{8443}}})
			require.Equal(t, []uint16{8443}, get()[0].Prefilter.Ports)
			creator.SyncRules([]typesv1.Rule{{ID: "new", State: map[string]any{"custom_state": "new"}}})
			require.Nil(t, get()[0].Prefilter)
			require.True(t, creator.RemoveRuleByID("new"))
			require.Empty(t, get())
			creator.RegisterRule(typesv1.Rule{ID: "new", State: map[string]any{"ports": []uint16{8080}}})
			require.Equal(t, []uint16{8080}, get()[0].Prefilter.Ports)
		})
	}
}
