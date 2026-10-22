//go:build experimental_signing

package ruleswatcher

import (
	"context"
	"testing"

	"github.com/kubescape/node-agent/pkg/rulemanager/rulecreator"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/bundle"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestEmbeddedRulesIgnoreMalformedStoredSpec(t *testing.T) {
	for _, stored := range []struct {
		name string
		spec any
	}{
		{"empty requirement", map[string]any{"rules": []any{map[string]any{"id": "R0001", "enabled": true, "profileDataRequired": map[string]any{"execs": ""}}}}},
		{"undecodable spec", "not a spec"},
	} {
		t.Run(stored.name, func(t *testing.T) {
			fragment := rulesObj("baseline", "kubescape", "", string(bundle.RuleClassBase), "R0001")
			require.NoError(t, signature.SignObject(profiles.NewRulesAdapter(fragment), signature.WithPrivateKey(testKey(t)), signature.WithEmbedContent(true)))
			client := newFakeK8sClient(t, fragment)
			creator := rulecreator.NewRuleCreator()
			w := NewRulesWatcher(client, creator, nil)
			w.SetTrustPolicy(&bundle.TrustPolicy{RuleClasses: map[bundle.RuleClass]bundle.RuleClassPolicy{
				bundle.RuleClassBase: {Signers: []string{signerOf(t, fragment)}, AllowedRuleIDs: []string{"*"}},
			}})
			require.NoError(t, w.InitialSync(context.Background()))
			require.Len(t, creator.CreateAllRules(), 1)
			resource := client.dyn.Resource(typesv1.RuleGvr).Namespace(fragment.Namespace)
			raw, err := resource.Get(context.Background(), fragment.Name, metav1.GetOptions{})
			require.NoError(t, err)
			raw.Object["spec"] = stored.spec
			_, err = resource.Update(context.Background(), raw, metav1.UpdateOptions{})
			require.NoError(t, err)
			require.NoError(t, w.InitialSync(context.Background()))
			all := creator.CreateAllRules()
			require.Len(t, all, 1)
			require.Equal(t, "R0001", all[0].ID)
			// Signing disabled still validates the stored spec as before.
			w.SetTrustPolicy(nil)
			require.NoError(t, w.InitialSync(context.Background()))
			require.Empty(t, creator.CreateAllRules())
		})
	}
}

type rawRulesAdapter struct {
	*profiles.RulesAdapter
	requirement any
}

func (a rawRulesAdapter) GetContent() any {
	content := a.RulesAdapter.GetContent().(map[string]any)
	content["spec"] = map[string]any{"rules": []any{map[string]any{"id": "R0001", "enabled": true, "profileDataRequired": a.requirement}}}
	return content
}

func TestAdmissionRejectsMalformedAuthenticatedRules(t *testing.T) {
	for _, requirement := range []any{map[string]any{"execs": ""}, map[string]any{"unknownSurface": "all"}, map[string]any{"execs": []any{map[string]any{"exct": "/bin/sh"}}}} {
		fragment := rulesObj("baseline", "kubescape", "", string(bundle.RuleClassBase), "R0001")
		adapter := rawRulesAdapter{profiles.NewRulesAdapter(fragment), requirement}
		require.NoError(t, signature.SignObject(adapter, signature.WithPrivateKey(testKey(t)), signature.WithEmbedContent(true)))
		policy := &bundle.TrustPolicy{RuleClasses: map[bundle.RuleClass]bundle.RuleClassPolicy{
			bundle.RuleClassBase: {Signers: []string{signerOf(t, fragment)}, AllowedRuleIDs: []string{"*"}},
		}}
		// Test direct admission as well as cluster conversion: typed decoding must
		// not silently erase unknown authenticated requirement fields.
		rules, tally := admitFragments([]*typesv1.Rules{fragment}, policy, true, nil)
		require.Empty(t, rules)
		require.Equal(t, 1, tally.rejected)
		creator := rulecreator.NewRuleCreator()
		w := NewRulesWatcher(newFakeK8sClient(t, fragment), creator, nil)
		w.SetTrustPolicy(policy)
		require.NoError(t, w.InitialSync(context.Background()))
		require.Empty(t, creator.CreateAllRules())
	}
}
