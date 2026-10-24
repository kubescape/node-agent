//go:build experimental_signing

package cache

import (
	"context"
	"fmt"
	mapset "github.com/deckarep/golang-set/v2"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	typesv1 "github.com/kubescape/node-agent/pkg/rulebindingmanager/types/v1"
	"github.com/kubescape/node-agent/pkg/rulemanager/rulecreator"
	rulemanagertypesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

func TestBundleOverrideOnByNameBinding(t *testing.T) {
	const ruleName = "unexpected_process_launched"

	rc := rulecreator.NewRuleCreator()
	// Cluster-wide baseline from a base-class fragment.
	rc.RegisterRule(rulemanagertypesv1.Rule{
		ID: "R0001", Name: ruleName, Enabled: true, Severity: 5,
		Expressions: rulemanagertypesv1.RuleExpressions{Message: "cluster baseline"},
		ClusterWide: true,
	})
	// Signed overlay for the "redis" bundle, same ID and name, retuned.
	rc.RegisterRule(rulemanagertypesv1.Rule{
		ID: "R0001", Name: ruleName, Enabled: true, Severity: 10,
		Expressions: rulemanagertypesv1.RuleExpressions{Message: "redis override"},
		Bundle:      "redis",
	})
	// An unrelated cluster rule, also bound by name, must be unaffected.
	rc.RegisterRule(rulemanagertypesv1.Rule{
		ID: "R0003", Name: "exec_from_malicious_source", Enabled: true, Severity: 7,
		ClusterWide: true,
	})

	c := NewCacheMock("")
	c.ruleCreator = rc

	rbName := "kubescape/rb-by-name"
	rb := typesv1.RuntimeAlertRuleBinding{
		Spec: typesv1.RuntimeAlertRuleBindingSpec{
			Rules: []typesv1.RuntimeAlertRuleBindingRule{
				{RuleName: ruleName},
				{RuleName: "exec_from_malicious_source"},
			},
		},
	}
	c.rbNameToRB.Set(rbName, rb)
	c.rbNameToRules.Set(rbName, c.createRules(rb.Spec.Rules))

	// Four pods, all selected by the same binding. Two opted into the "redis"
	// bundle from DIFFERENT namespaces, one opted into another bundle, one did
	// not opt in at all.
	pods := []*corev1.Pod{
		podWithBundle("redis", "redis-0", "redis"),
		podWithBundle("team-a", "cache-0", "redis"),
		podWithBundle("other", "pg-0", "postgres"),
		podWithBundle("other", "api-0", ""),
	}
	for _, p := range pods {
		c.podToRBNames.Set(uniqueName(p), mapset.NewSet[string](rbName))
		c.setPodBundle(p)
	}

	assertOverridden := func(t *testing.T, namespace, name string) {
		t.Helper()
		got := c.ListRulesForPod(namespace, name)
		require.Len(t, got, 2, "expected exactly one R0001 plus R0003, got %v", got)

		var r0001 []rulemanagertypesv1.Rule
		for _, r := range got {
			if r.ID == "R0001" {
				r0001 = append(r0001, r)
			}
		}
		require.Len(t, r0001, 1, "the override must replace the base rule, not be added next to it")
		assert.Equal(t, "redis", r0001[0].Bundle)
		assert.False(t, r0001[0].ClusterWide)
		assert.Equal(t, 10, r0001[0].Severity)
		assert.Equal(t, "redis override", r0001[0].Expressions.Message)
	}

	assertBaseline := func(t *testing.T, namespace, name string) {
		t.Helper()
		got := c.ListRulesForPod(namespace, name)
		require.Len(t, got, 2, "expected exactly one R0001 plus R0003, got %v", got)

		var r0001 []rulemanagertypesv1.Rule
		for _, r := range got {
			if r.ID == "R0001" {
				r0001 = append(r0001, r)
			}
		}
		require.Len(t, r0001, 1, "the redis overlay must not leak outside its bundle")
		assert.True(t, r0001[0].ClusterWide)
		assert.Empty(t, r0001[0].Bundle)
		assert.Equal(t, 5, r0001[0].Severity)
		assert.Equal(t, "cluster baseline", r0001[0].Expressions.Message)
	}

	t.Run("pod bound to the bundle gets the overlay", func(t *testing.T) {
		assertOverridden(t, "redis", "redis-0")
	})

	t.Run("bundle crosses namespaces", func(t *testing.T) {
		// Same bundle, entirely different namespace: the overlay still applies.
		// This is what scoping by bundle buys over scoping by namespace.
		assertOverridden(t, "team-a", "cache-0")
	})

	t.Run("pod bound to another bundle keeps the base rule", func(t *testing.T) {
		assertBaseline(t, "other", "pg-0")
	})

	t.Run("pod with no bundle label keeps the base rule", func(t *testing.T) {
		assertBaseline(t, "other", "api-0")
	})

	t.Run("pod unknown to the bundle map keeps the base rule", func(t *testing.T) {
		// Safe default: an unknown pod is treated as bound to no bundle.
		c.podToRBNames.Set("ghost/ghost-0", mapset.NewSet[string](rbName))
		assertBaseline(t, "ghost", "ghost-0")
	})

	t.Run("binding contributes both variants before scoping", func(t *testing.T) {
		// The cache must hold BOTH R0001 variants per binding; scoping picks one
		// per pod. If this drops to one, the override above is accidental.
		rules, ok := c.rbNameToRules.Load(rbName)
		require.True(t, ok)
		count := 0
		for _, r := range rules {
			if r.ID == "R0001" {
				count++
			}
		}
		assert.Equal(t, 2, count, "createRules must expand a by-name entry to every variant")
	})
}

// podWithBundle builds a pod carrying (or not carrying) the user-defined-profile
// label that opts a workload into a signed bundle.
func podWithBundle(namespace, name, bundleName string) *corev1.Pod {
	labels := map[string]string{}
	if bundleName != "" {
		labels[helpersv1.UserDefinedProfileMetadataKey] = bundleName
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: labels},
	}
}

// TestPodBundleTracking pins the pod -> bundle bookkeeping the scoping depends
// on: the label is read on add and on every update, and the entry disappears
// with the pod (or with the label).
func TestPodBundleTracking(t *testing.T) {
	c := NewCacheMock("")
	c.config.IgnoreRuleBindings = true // pod bundles are tracked in this mode too

	pod := podWithBundle("redis", "redis-0", "redis")
	c.AddHandler(context.Background(), pod)
	assert.Equal(t, "redis", c.bundleForPod("redis/redis-0"))

	// Re-labelled to another bundle.
	c.ModifyHandler(context.Background(), podWithBundle("redis", "redis-0", "postgres"))
	assert.Equal(t, "postgres", c.bundleForPod("redis/redis-0"))

	// Opted out: a stale entry would keep applying an overlay.
	c.ModifyHandler(context.Background(), podWithBundle("redis", "redis-0", ""))
	assert.Empty(t, c.bundleForPod("redis/redis-0"))

	// Deleted: the entry must not survive for a recycled pod ID.
	c.ModifyHandler(context.Background(), podWithBundle("redis", "redis-0", "redis"))
	require.Equal(t, "redis", c.bundleForPod("redis/redis-0"))
	c.DeleteHandler(context.Background(), podWithBundle("redis", "redis-0", "redis"))
	assert.Empty(t, c.bundleForPod("redis/redis-0"))

	// An entirely unknown pod resolves to no bundle.
	assert.Empty(t, c.bundleForPod("nowhere/nothing"))
}

// TestListRulesForPod_IgnoreRuleBindingsScopesByBundle covers the other
// ListRulesForPod branch: with IgnoreRuleBindings the rules come straight from
// the rule creator, and they must still be scoped to the pod's bundle.
func TestListRulesForPod_IgnoreRuleBindingsScopesByBundle(t *testing.T) {
	rc := rulecreator.NewRuleCreator()
	rc.RegisterRule(rulemanagertypesv1.Rule{
		ID: "R0001", Name: "r1", Enabled: true, Severity: 5,
		Expressions: rulemanagertypesv1.RuleExpressions{Message: "cluster baseline"},
		ClusterWide: true,
	})
	rc.RegisterRule(rulemanagertypesv1.Rule{
		ID: "R0001", Name: "r1", Enabled: true, Severity: 10,
		Expressions: rulemanagertypesv1.RuleExpressions{Message: "redis override"},
		Bundle:      "redis",
	})

	c := NewCacheMock("")
	c.ruleCreator = rc
	c.config.IgnoreRuleBindings = true

	c.AddHandler(context.Background(), podWithBundle("anywhere", "redis-0", "redis"))
	c.AddHandler(context.Background(), podWithBundle("anywhere", "plain-0", ""))

	inBundle := c.ListRulesForPod("anywhere", "redis-0")
	require.Len(t, inBundle, 1)
	assert.Equal(t, "redis override", inBundle[0].Expressions.Message)

	outside := c.ListRulesForPod("anywhere", "plain-0")
	require.Len(t, outside, 1)
	assert.Equal(t, "cluster baseline", outside[0].Expressions.Message)
}

func TestBundleChangesInvalidateCachedRules(t *testing.T) {
	for _, ignoreBindings := range []bool{false, true} {
		t.Run(fmt.Sprintf("ignoreBindings=%t", ignoreBindings), func(t *testing.T) {
			rc := rulecreator.NewRuleCreator()
			rc.RegisterRule(rulemanagertypesv1.Rule{ID: "R0001", ClusterWide: true, Severity: 5})
			rc.RegisterRule(rulemanagertypesv1.Rule{ID: "R0001", Bundle: "redis", Severity: 10})
			c := NewCacheMock("")
			c.ruleCreator = rc
			c.config.IgnoreRuleBindings = ignoreBindings
			pod := podWithBundle("ns", "pod", "redis")
			c.AddHandler(context.Background(), pod)
			if !ignoreBindings {
				c.rbNameToRules.Set("rb", rc.CreateAllRules())
				c.podToRBNames.Set("ns/pod", mapset.NewSet[string]("rb"))
			}
			require.Equal(t, 10, c.ListRulesForPod("ns", "pod")[0].Severity)
			c.ModifyHandler(context.Background(), podWithBundle("ns", "pod", ""))
			require.Equal(t, 5, c.ListRulesForPod("ns", "pod")[0].Severity)
			c.ModifyHandler(context.Background(), pod)
			require.Equal(t, 10, c.ListRulesForPod("ns", "pod")[0].Severity)
			c.DeleteHandler(context.Background(), pod)
			_, cached := c.rulesForPod.Get("ns/pod")
			require.False(t, cached, "a recycled pod ID must not inherit a cached overlay")
		})
	}
}
