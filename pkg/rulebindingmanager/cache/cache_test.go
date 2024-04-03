package cache

import (
	"context"
	"node-agent/pkg/k8sclient"
	typesv1 "node-agent/pkg/rulebindingmanager/types/v1"
	"node-agent/pkg/ruleengine"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func NewCacheMock(nodeName string) *RBCache {
	return &RBCache{
		nodeName:         nodeName,
		allPods:          mapset.NewSet[string](),
		k8sClient:        &k8sclient.K8sClientMock{},
		ruleCreator:      &ruleengine.RuleCreatorMock{},
		globalRBNames:    mapset.NewSet[string](),
		podToRBNames:     maps.SafeMap[string, mapset.Set[string]]{},
		rbNameToPodNames: maps.SafeMap[string, mapset.Set[string]]{},
	}
}
func TestRuntimeObjAddHandler(t *testing.T) {
	type rules struct {
		ruleID string
	}
	type args struct {
		c   *RBCache
		pod *corev1.Pod
		rb  []typesv1.RuntimeAlertRuleBinding
	}
	tests := []struct {
		name          string
		args          args
		expectedRules []rules
	}{
		{
			name: "Add a pod to the cache",
			args: args{
				c: NewCacheMock(""),
				pod: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "testPod",
						Namespace: "testNamespace",
						Labels: map[string]string{
							"app": "testPod",
						},
					},
				},
				rb: []typesv1.RuntimeAlertRuleBinding{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "testRB",
							Namespace: "testNamespace",
						},
						Spec: typesv1.RuntimeAlertRuleBindingSpec{
							PodSelector: metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": "testPod",
								},
							},
							Rules: []typesv1.RuntimeAlertRuleBindingRule{
								{
									RuleID: "R0001",
								},
							},
						},
					},
				},
			},
			expectedRules: []rules{
				{
					ruleID: "R0001",
				},
			},
		},
		{
			name: "Pod with MatchExpressions",
			args: args{
				c: NewCacheMock(""),
				pod: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "testPod",
						Namespace: "testNamespace",
						Labels: map[string]string{
							"app": "testPod",
						},
					},
				},
				rb: []typesv1.RuntimeAlertRuleBinding{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "testRB",
							Namespace: "testNamespace",
						},
						Spec: typesv1.RuntimeAlertRuleBindingSpec{
							PodSelector: metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{
										Key:      "app",
										Operator: metav1.LabelSelectorOpIn,
										Values:   []string{"testPod"},
									},
								},
							},
							Rules: []typesv1.RuntimeAlertRuleBindingRule{
								{
									RuleID: "R0001",
								},
							},
						},
					},
				},
			},
			expectedRules: []rules{
				{
					ruleID: "R0001",
				},
			},
		},
		{
			name: "Pod with mismatch labels",
			args: args{
				c: NewCacheMock(""),
				pod: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "testPod",
						Namespace: "testNamespace",
						Labels: map[string]string{
							"app": "testPod",
						},
					},
				},
				rb: []typesv1.RuntimeAlertRuleBinding{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "testRB",
							Namespace: "testNamespace",
						},
						Spec: typesv1.RuntimeAlertRuleBindingSpec{
							PodSelector: metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": "testPod1",
								},
							},
							Rules: []typesv1.RuntimeAlertRuleBindingRule{
								{
									RuleID: "R0001",
								},
							},
						},
					},
				},
			},
			expectedRules: []rules{},
		},
		// TODO: test namespace selector
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := range tt.args.rb {
				tt.args.c.addRuleBinding(&tt.args.rb[i])
			}
			tt.args.c.addPod(context.Background(), tt.args.pod)
			r := tt.args.c.ListRulesForPod(tt.args.pod.GetNamespace(), tt.args.pod.GetName())
			assert.Equal(t, len(tt.expectedRules), len(r))
			for i := range r {
				assert.Equal(t, tt.expectedRules[i].ruleID, r[i].ID())

			}
		})

	}
}
func TestDeletePod(t *testing.T) {
	tests := []struct {
		setup      func(*RBCache)
		name       string
		uniqueName string
	}{
		{
			name:       "Test with existing pod",
			uniqueName: "default/pod-1",
			setup: func(c *RBCache) {
				c.allPods.Add("default/pod-1")
				c.podToRBNames.Set("default/pod-1", mapset.NewSet[string]("rb-1"))
				c.rbNameToPodNames.Set("rb-1", mapset.NewSet[string]("default/pod-1"))
			},
		},
		{
			name:       "Test with non-existing pod",
			uniqueName: "default/pod-2",
			setup:      func(c *RBCache) {},
		},
		{
			name:       "Test pod not found",
			uniqueName: "default/pod-2",
			setup: func(c *RBCache) {
				c.allPods.Add("default/pod-1")
				c.podToRBNames.Set("default/pod-1", mapset.NewSet[string]("rb-1"))
				c.rbNameToPodNames.Set("rb-1", mapset.NewSet[string]("default/pod-1"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &RBCache{
				allPods:          mapset.NewSet[string](),
				podToRBNames:     maps.SafeMap[string, mapset.Set[string]]{},
				rbNameToPodNames: maps.SafeMap[string, mapset.Set[string]]{},
			}
			tt.setup(c)

			c.deletePod(tt.uniqueName)

			assert.False(t, c.allPods.Contains(tt.uniqueName))
			assert.False(t, c.podToRBNames.Has(tt.uniqueName))
			for _, rbName := range c.rbNameToPodNames.Keys() {
				assert.False(t, c.rbNameToPodNames.Get(rbName).Contains(tt.uniqueName))
			}
		})
	}
}
func TestCreateRule(t *testing.T) {
	c := NewCacheMock("")
	tests := []struct {
		name     string
		rule     *typesv1.RuntimeAlertRuleBindingRule
		expected []ruleengine.RuleEvaluator
	}{
		{
			name: "Test with RuleID",
			rule: &typesv1.RuntimeAlertRuleBindingRule{
				RuleID:     "rule-1",
				Parameters: map[string]interface{}{"param1": "value1"},
			},
			expected: []ruleengine.RuleEvaluator{&ruleengine.RuleMock{RuleID: "rule-1", RuleParameters: map[string]interface{}{"param1": "value1"}}},
		},
		{
			name: "Test with RuleName",
			rule: &typesv1.RuntimeAlertRuleBindingRule{
				RuleName:   "rule-1",
				Parameters: map[string]interface{}{"param1": "value1"},
			},
			expected: []ruleengine.RuleEvaluator{&ruleengine.RuleMock{RuleName: "rule-1", RuleParameters: map[string]interface{}{"param1": "value1"}}},
		},
		{
			name: "Test with RuleTags",
			rule: &typesv1.RuntimeAlertRuleBindingRule{
				RuleTags:   []string{"tag1", "tag2"},
				Parameters: map[string]interface{}{"param1": "value1"},
			},
			expected: []ruleengine.RuleEvaluator{&ruleengine.RuleMock{RuleName: "tag1", RuleParameters: map[string]interface{}{"param1": "value1"}}, &ruleengine.RuleMock{RuleName: "tag2", RuleParameters: map[string]interface{}{"param1": "value1"}}},
		},
		{
			name:     "Test with no RuleID, RuleName, or RuleTags",
			rule:     &typesv1.RuntimeAlertRuleBindingRule{},
			expected: []ruleengine.RuleEvaluator{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.createRule(tt.rule)
			assert.Equal(t, len(tt.expected), len(result))
			for i := range result {
				assert.Equal(t, tt.expected[i].Name(), result[i].Name())
				assert.Equal(t, tt.expected[i].ID(), result[i].ID())
				assert.Equal(t, tt.expected[i].GetParameters(), result[i].GetParameters())
			}
		})
	}
}
func TestIsCached(t *testing.T) {
	c := &RBCache{
		allPods: mapset.NewSet[string]("default/pod-1"),
	}
	c.rbNameToRB.Set("default/rule-1", typesv1.RuntimeAlertRuleBinding{})

	tests := []struct {
		name      string
		kind      string
		namespace string
		rName     string
		expected  bool
	}{
		{
			name:      "Test with cached Pod",
			kind:      "Pod",
			namespace: "default",
			rName:     "pod-1",
			expected:  true,
		},
		{
			name:      "Test with uncached Pod",
			kind:      "Pod",
			namespace: "default",
			rName:     "pod-2",
			expected:  false,
		},
		{
			name:      "Test with cached RuntimeRuleAlertBinding",
			kind:      "RuntimeRuleAlertBinding",
			namespace: "default",
			rName:     "rule-1",
			expected:  true,
		},
		{
			name:      "Test with uncached RuntimeRuleAlertBinding",
			kind:      "RuntimeRuleAlertBinding",
			namespace: "default",
			rName:     "rule-2",
			expected:  false,
		},
		{
			name:      "Test with unknown kind",
			kind:      "Unknown",
			namespace: "default",
			rName:     "unknown-1",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.IsCached(tt.kind, tt.namespace, tt.rName)
			assert.Equal(t, tt.expected, result)
		})
	}
}
func TestDeleteHandler(t *testing.T) {
	type expected struct {
		pod  string
		rule string
	}
	tests := []struct {
		name     string
		obj      *unstructured.Unstructured
		expected expected
	}{
		{
			name: "Test with Pod kind",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"kind": "Pod",
					"metadata": map[string]interface{}{
						"name":      "pod-1",
						"namespace": "default",
					},
				},
			},
			expected: expected{
				pod:  "default/pod-1",
				rule: "default/rule-1",
			},
		},
		{
			name: "Test with RuntimeRuleBindingAlert kind",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"kind": "RuntimeRuleAlertBinding",
					"metadata": map[string]interface{}{
						"name":      "rule-1",
						"namespace": "default",
					},
				},
			},
			expected: expected{
				pod:  "default/pod-1",
				rule: "default/rule-1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &RBCache{
				allPods:       mapset.NewSet[string](tt.expected.pod),
				globalRBNames: mapset.NewSet[string](tt.expected.rule),
			}
			c.DeleteHandler(context.Background(), tt.obj)
			if tt.obj.GetKind() == "Pod" {
				assert.False(t, c.allPods.Contains(tt.expected.pod))
				assert.True(t, c.globalRBNames.Contains(tt.expected.rule))
			} else if tt.obj.GetKind() == "RuntimeRuleAlertBinding" {
				assert.True(t, c.allPods.Contains(tt.expected.pod))
				assert.False(t, c.globalRBNames.Contains(tt.expected.rule))
			} else {
				assert.True(t, c.allPods.Contains(tt.expected.pod))
				assert.True(t, c.globalRBNames.Contains(tt.expected.rule))
			}
		})
	}
}

func TestModifyHandler(t *testing.T) {
	type expected struct {
		pod  string
		rule string
	}
	tests := []struct {
		name     string
		obj      *unstructured.Unstructured
		expected expected
		addedPod bool
		addedRB  bool
	}{
		{
			name: "Test with Pod kind",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"kind": "Pod",
					"metadata": map[string]interface{}{
						"name":      "pod-1",
						"namespace": "default",
					},
				},
			},
			addedPod: true,
			addedRB:  false,
			expected: expected{
				pod:  "default/pod-1",
				rule: "default/rule-1",
			},
		},
		{
			name: "Test with RuntimeRuleBindingAlert kind",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"kind": "RuntimeRuleAlertBinding",
					"metadata": map[string]interface{}{
						"name":      "rule-1",
						"namespace": "default",
					},
				},
			},
			addedPod: false,
			addedRB:  true,
			expected: expected{
				pod:  "default/pod-1",
				rule: "default/rule-1",
			},
		},
		{
			name: "Test with invalid RuntimeRuleBindingAlert kind",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "RuntimeAlertRuleBinding",
					"metadata": map[string]interface{}{
						"name":      "rule-1",
						"namespace": "default",
					},
					"spec": "invalid",
				},
			},
			addedPod: false,
			addedRB:  false,
			expected: expected{
				pod:  "default/pod-1",
				rule: "default/rule-1",
			},
		},
		{
			name: "Test with invalid Pod kind",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "Pod",
					"metadata": map[string]interface{}{
						"name":      "pod-1",
						"namespace": "default",
					},
					"spec": map[string]interface{}{
						"containers": "invalid",
					},
				},
			},
			addedPod: false,
			addedRB:  false,
			expected: expected{
				pod:  "default/pod-1",
				rule: "default/rule-1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			c := NewCacheMock("")

			c.ModifyHandler(context.Background(), tt.obj)

			if tt.addedPod {
				assert.True(t, c.allPods.Contains(tt.expected.pod))
				assert.False(t, c.globalRBNames.Contains(tt.expected.rule))
			}
			if tt.addedRB {
				assert.False(t, c.allPods.Contains(tt.expected.pod))
				assert.True(t, c.globalRBNames.Contains(tt.expected.rule))
			}
			if !tt.addedPod && !tt.addedRB {
				assert.False(t, c.allPods.Contains(tt.expected.pod))
				assert.False(t, c.globalRBNames.Contains(tt.expected.rule))
			}
		})
	}
}

func TestAddHandler(t *testing.T) {
	type expected struct {
		pod  string
		rule string
	}
	tests := []struct {
		name     string
		obj      *unstructured.Unstructured
		expected expected
		addedPod bool
		addedRB  bool
	}{
		{
			name: "Test with Pod kind",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"kind": "Pod",
					"metadata": map[string]interface{}{
						"name":      "pod-1",
						"namespace": "default",
					},
				},
			},
			addedPod: true,
			addedRB:  false,
			expected: expected{
				pod:  "default/pod-1",
				rule: "default/rule-1",
			},
		},
		{
			name: "Test with RuntimeRuleBindingAlert kind",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"kind": "RuntimeRuleAlertBinding",
					"metadata": map[string]interface{}{
						"name":      "rule-1",
						"namespace": "default",
					},
				},
			},
			addedPod: false,
			addedRB:  true,
			expected: expected{
				pod:  "default/pod-1",
				rule: "default/rule-1",
			},
		},
		{
			name: "Test with invalid RuntimeRuleBindingAlert kind",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "RuntimeAlertRuleBinding",
					"metadata": map[string]interface{}{
						"name":      "rule-1",
						"namespace": "default",
					},
					"spec": "invalid",
				},
			},
			addedPod: false,
			addedRB:  false,
			expected: expected{
				pod:  "default/pod-1",
				rule: "default/rule-1",
			},
		},
		{
			name: "Test with invalid Pod kind",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "Pod",
					"metadata": map[string]interface{}{
						"name":      "pod-1",
						"namespace": "default",
					},
					"spec": map[string]interface{}{
						"containers": "invalid",
					},
				},
			},
			addedPod: false,
			addedRB:  false,
			expected: expected{
				pod:  "default/pod-1",
				rule: "default/rule-1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			c := NewCacheMock("")

			c.AddHandler(context.Background(), tt.obj)

			if tt.addedPod {
				assert.True(t, c.allPods.Contains(tt.expected.pod))
				assert.False(t, c.globalRBNames.Contains(tt.expected.rule))
			}
			if tt.addedRB {
				assert.False(t, c.allPods.Contains(tt.expected.pod))
				assert.True(t, c.globalRBNames.Contains(tt.expected.rule))
			}
			if !tt.addedPod && !tt.addedRB {
				assert.False(t, c.allPods.Contains(tt.expected.pod))
				assert.False(t, c.globalRBNames.Contains(tt.expected.rule))
			}
		})
	}
}
