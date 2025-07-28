package cache

import (
	"context"
	"fmt"
	"slices"
	"testing"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/node-agent/mocks"
	"github.com/kubescape/node-agent/pkg/rulebindingmanager"
	typesv1 "github.com/kubescape/node-agent/pkg/rulebindingmanager/types/v1"
	rulemanagertypesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

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
				assert.Equal(t, tt.expectedRules[i].ruleID, r[i].Spec.ID)

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
				c.rbNameToPods.Set("rb-1", mapset.NewSet[string]("default/pod-1"))
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
				c.rbNameToPods.Set("rb-1", mapset.NewSet[string]("default/pod-1"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &RBCache{
				allPods:      mapset.NewSet[string](),
				podToRBNames: maps.SafeMap[string, mapset.Set[string]]{},
				rbNameToPods: maps.SafeMap[string, mapset.Set[string]]{},
			}
			tt.setup(c)

			c.deletePod(tt.uniqueName)

			assert.False(t, c.allPods.Contains(tt.uniqueName))
			assert.False(t, c.podToRBNames.Has(tt.uniqueName))
			for _, rbName := range c.rbNameToPods.Keys() {
				assert.False(t, c.rbNameToPods.Get(rbName).Contains(tt.uniqueName))
			}
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
		obj      runtime.Object
		expected expected
	}{
		{
			name: "Test with Pod kind",
			obj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod-1",
					Namespace: "default",
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
				allPods: mapset.NewSet[string](tt.expected.pod),
			}
			c.DeleteHandler(context.Background(), tt.obj)
			if _, ok := tt.obj.(*corev1.Pod); ok {
				assert.False(t, c.allPods.Contains(tt.expected.pod))
			} else {
				assert.True(t, c.allPods.Contains(tt.expected.pod))
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
		obj      runtime.Object
		expected expected
		addedPod bool
		addedRB  bool
	}{
		{
			name: "Test with Pod kind",
			obj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod-1",
					Namespace: "default",
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
			}
			if tt.addedRB {
				assert.False(t, c.allPods.Contains(tt.expected.pod))
			}
			if !tt.addedPod && !tt.addedRB {
				assert.False(t, c.allPods.Contains(tt.expected.pod))
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
		obj      runtime.Object
		expected expected
		addedPod bool
		addedRB  bool
	}{
		{
			name: "Test with Pod kind",
			obj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod-1",
					Namespace: "default",
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
			}
			if tt.addedRB {
				assert.False(t, c.allPods.Contains(tt.expected.pod))
			}
			if !tt.addedPod && !tt.addedRB {
				assert.False(t, c.allPods.Contains(tt.expected.pod))
			}
		})
	}
}
func TestDeleteRuleBinding(t *testing.T) {

	tests := []struct {
		podToRBNames         map[string][]string
		expectedPodToRBNames map[string][]string
		name                 string
		uniqueName           string
	}{
		{
			name:                 "Test with valid unique name without pods",
			uniqueName:           "test-unique-name",
			podToRBNames:         map[string][]string{},
			expectedPodToRBNames: map[string][]string{},
		},
		{
			name:       "Test with valid unique name one pod",
			uniqueName: "test-unique-name",
			podToRBNames: map[string][]string{
				"default/pod-1": {"test-unique-name"},
			},
			expectedPodToRBNames: map[string][]string{},
		},
		{
			name:       "Delete all pods with the same unique name",
			uniqueName: "test-unique-name",
			podToRBNames: map[string][]string{
				"default/pod-1": {"test-unique-name"},
				"default/pod-2": {"test-unique-name"},
				"default/pod-3": {"test-unique-name"},
			},
			expectedPodToRBNames: map[string][]string{},
		},
		{
			name:       "Delete one pod with the same unique name",
			uniqueName: "test-unique-name",
			podToRBNames: map[string][]string{
				"default/pod-1": {"test-unique-name"},
				"default/pod-2": {"test-unique-name", "test-unique-name-2", "test-unique-name-3"},
				"default/pod-3": {"test-unique-name-2", "test-unique-name-3"},
			},
			expectedPodToRBNames: map[string][]string{
				"default/pod-2": {"test-unique-name-2", "test-unique-name-3"},
				"default/pod-3": {"test-unique-name-2", "test-unique-name-3"},
			},
		},
		{
			name:       "Do not delete any",
			uniqueName: "test-unique-name",
			podToRBNames: map[string][]string{
				"default/pod-2": {"test-unique-name-2", "test-unique-name-3"},
				"default/pod-3": {"test-unique-name-2", "test-unique-name-3"},
			},
			expectedPodToRBNames: map[string][]string{
				"default/pod-2": {"test-unique-name-2", "test-unique-name-3"},
				"default/pod-3": {"test-unique-name-2", "test-unique-name-3"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCacheMock("")

			for k, v := range tt.podToRBNames {
				for _, s := range v {
					c.rbNameToRB.Set(s, typesv1.RuntimeAlertRuleBinding{})
					c.rbNameToRules.Set(s, []rulemanagertypesv1.Rule{rulemanagertypesv1.Rule{}})

					if !c.rbNameToPods.Has(s) {
						c.rbNameToPods.Set(s, mapset.NewSet[string]())
					}
					c.rbNameToPods.Get(s).Add(k)

					if !c.podToRBNames.Has(k) {
						c.podToRBNames.Set(k, mapset.NewSet[string]())
					}
					c.podToRBNames.Get(k).Add(s)
				}

			}

			c.deleteRuleBinding(tt.uniqueName)

			assert.False(t, c.rbNameToPods.Has(tt.uniqueName))
			assert.False(t, c.rbNameToRB.Has(tt.uniqueName))
			assert.False(t, c.rbNameToRules.Has(tt.uniqueName))
			for k, v := range tt.expectedPodToRBNames {
				slices.Sort(v)
				tmp := c.podToRBNames.Get(k).ToSlice()
				slices.Sort(tmp)
				assert.Equal(t, v, tmp)
			}
		})
	}
}

func TestAddRuleBinding(t *testing.T) {

	defer func() {
		mocks.NAMESPACE = ""
	}()

	k8sClient := k8sinterface.NewKubernetesApiMock()
	var r []runtime.Object
	mocks.NAMESPACE = "default"
	r = append(r, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: mocks.NAMESPACE, Labels: map[string]string{"app": mocks.NAMESPACE}}})
	r = append(r, mocks.GetRuntime(mocks.TestKindPod, mocks.TestCollection))
	r = append(r, mocks.GetRuntime(mocks.TestKindPod, mocks.TestNginx))

	mocks.NAMESPACE = "other"
	r = append(r, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: mocks.NAMESPACE, Labels: map[string]string{"app": mocks.NAMESPACE}}})
	r = append(r, mocks.GetRuntime(mocks.TestKindPod, mocks.TestCollection))
	r = append(r, mocks.GetRuntime(mocks.TestKindPod, mocks.TestNginx))

	mocks.NAMESPACE = "test"
	r = append(r, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: mocks.NAMESPACE, Labels: map[string]string{"app": mocks.NAMESPACE}}})
	r = append(r, mocks.GetRuntime(mocks.TestKindPod, mocks.TestCollection))
	r = append(r, mocks.GetRuntime(mocks.TestKindPod, mocks.TestNginx))

	k8sClient.KubernetesClient = k8sfake.NewSimpleClientset(r...)

	tests := []struct {
		rb                   *typesv1.RuntimeAlertRuleBinding
		name                 string
		expectedNotifiedPods []string
		invalidRB            bool
	}{
		{
			name: "Add roleBinding",
			rb: &typesv1.RuntimeAlertRuleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "rb1",
				},
				Spec: typesv1.RuntimeAlertRuleBindingSpec{
					Rules: []typesv1.RuntimeAlertRuleBindingRule{
						{
							RuleID: "R0001",
						},
					},
				},
			},
			expectedNotifiedPods: []string{
				"default/collection-94c495554-z8s5k",
				"default/nginx-77b4fdf86c-hp4x5",
				"other/collection-94c495554-z8s5k",
				"other/nginx-77b4fdf86c-hp4x5",
				"test/collection-94c495554-z8s5k",
				"test/nginx-77b4fdf86c-hp4x5",
			},
		},
		{
			name: "Add roleBinding namespace 'other'",
			rb: &typesv1.RuntimeAlertRuleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "rb1",
				},
				Spec: typesv1.RuntimeAlertRuleBindingSpec{
					NamespaceSelector: metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "app",
								Operator: metav1.LabelSelectorOpIn,
								Values:   []string{"other"},
							},
						},
					},
					Rules: []typesv1.RuntimeAlertRuleBindingRule{
						{
							RuleID: "R0001",
						},
						{
							RuleID: "R0002",
						},
					},
				},
			},
			expectedNotifiedPods: []string{
				"other/collection-94c495554-z8s5k",
				"other/nginx-77b4fdf86c-hp4x5",
			},
		},
		{
			name: "Add namespaced roleBinding",
			rb: &typesv1.RuntimeAlertRuleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "rb1",
					Namespace: "other",
				},
				Spec: typesv1.RuntimeAlertRuleBindingSpec{
					NamespaceSelector: metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "app",
								Operator: metav1.LabelSelectorOpIn,
								Values:   []string{"other"},
							},
						},
					},
					Rules: []typesv1.RuntimeAlertRuleBindingRule{
						{
							RuleID: "R0001",
						},
						{
							RuleID: "R0002",
						},
					},
				},
			},
			expectedNotifiedPods: []string{
				"other/collection-94c495554-z8s5k",
				"other/nginx-77b4fdf86c-hp4x5",
			},
		},
		{
			name: "Add namespaced roleBinding without pods",
			rb: &typesv1.RuntimeAlertRuleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "rb1",
					Namespace: "blabla",
				},
				Spec: typesv1.RuntimeAlertRuleBindingSpec{
					NamespaceSelector: metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "app",
								Operator: metav1.LabelSelectorOpIn,
								Values:   []string{"other"},
							},
						},
					},
					Rules: []typesv1.RuntimeAlertRuleBindingRule{
						{
							RuleID: "R0001",
						},
						{
							RuleID: "R0002",
						},
					},
				},
			},
			expectedNotifiedPods: []string{},
		},
		{
			name: "Add roleBinding exclude namespace 'other'",
			rb: &typesv1.RuntimeAlertRuleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "rb1",
				},
				Spec: typesv1.RuntimeAlertRuleBindingSpec{
					NamespaceSelector: metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "app",
								Operator: metav1.LabelSelectorOpNotIn,
								Values:   []string{"other"},
							},
						},
					},
					Rules: []typesv1.RuntimeAlertRuleBindingRule{
						{
							RuleID: "R0001",
						},
						{
							RuleID: "R0002",
						},
					},
				},
			},
			expectedNotifiedPods: []string{
				"default/collection-94c495554-z8s5k",
				"default/nginx-77b4fdf86c-hp4x5",
				"test/collection-94c495554-z8s5k",
				"test/nginx-77b4fdf86c-hp4x5",
			},
		},
		{
			name: "Add roleBinding MatchLabels",
			rb: &typesv1.RuntimeAlertRuleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "rb1",
				},
				Spec: typesv1.RuntimeAlertRuleBindingSpec{
					NamespaceSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "test",
						},
					},
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "collection",
						},
					},
					Rules: []typesv1.RuntimeAlertRuleBindingRule{
						{
							RuleID: "R0001",
						},
						{
							RuleID: "R0002",
						},
					},
				},
			},
			expectedNotifiedPods: []string{
				"test/collection-94c495554-z8s5k",
			},
		},
		{
			name: "Namespace does not exists",
			rb: &typesv1.RuntimeAlertRuleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "rb1",
				},
				Spec: typesv1.RuntimeAlertRuleBindingSpec{
					NamespaceSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "bla",
						},
					},
					Rules: []typesv1.RuntimeAlertRuleBindingRule{
						{
							RuleID: "R0001",
						},
					},
				},
			},
			expectedNotifiedPods: []string{},
		},
		{
			name: "Invalid ns selector",
			rb: &typesv1.RuntimeAlertRuleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "rb1",
				},
				Spec: typesv1.RuntimeAlertRuleBindingSpec{
					NamespaceSelector: metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "app",
								Operator: metav1.LabelSelectorOperator("invalid"),
								Values:   []string{"other"},
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
			invalidRB:            true,
			expectedNotifiedPods: []string{},
		},
		{
			name: "Invalid label selector",
			rb: &typesv1.RuntimeAlertRuleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "rb1",
				},
				Spec: typesv1.RuntimeAlertRuleBindingSpec{
					PodSelector: metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "app",
								Operator: metav1.LabelSelectorOperator("invalid"),
								Values:   []string{"other"},
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
			invalidRB:            true,
			expectedNotifiedPods: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCacheMock("")
			c.k8sClient = k8sClient

			c.addRuleBinding(tt.rb)

			rbName := uniqueName(tt.rb)

			if tt.invalidRB {
				assert.False(t, c.rbNameToPods.Has(rbName))
				assert.False(t, c.rbNameToRB.Has(rbName))
				assert.False(t, c.rbNameToRules.Has(rbName))
				return
			}

			assert.True(t, c.rbNameToPods.Has(rbName))
			assert.True(t, c.rbNameToRB.Has(rbName))
			assert.True(t, c.rbNameToRules.Has(rbName))

			for _, pod := range tt.expectedNotifiedPods {
				assert.True(t, c.podToRBNames.Has(pod))
				assert.True(t, c.podToRBNames.Get(pod).Contains(rbName))
			}

		})
	}
}

func TestDiff(t *testing.T) {
	tests := []struct {
		name string
		a, b []rulebindingmanager.RuleBindingNotify
		want []rulebindingmanager.RuleBindingNotify
	}{
		{
			name: "Test with non-overlapping slices",
			a: []rulebindingmanager.RuleBindingNotify{
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-1", Namespace: "default"}},
					Action: rulebindingmanager.Added,
				},
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-2", Namespace: "default"}},
					Action: rulebindingmanager.Added,
				},
			},
			b: []rulebindingmanager.RuleBindingNotify{
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-2", Namespace: "default-2"}},
					Action: rulebindingmanager.Removed,
				},
			},
			want: []rulebindingmanager.RuleBindingNotify{
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-1", Namespace: "default"}},
					Action: rulebindingmanager.Added,
				},
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-2", Namespace: "default"}},
					Action: rulebindingmanager.Added,
				},
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-2", Namespace: "default-2"}},
					Action: rulebindingmanager.Removed,
				},
			},
		},
		{
			name: "Test with overlapping slices",
			a: []rulebindingmanager.RuleBindingNotify{
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-1", Namespace: "default"}},
					Action: rulebindingmanager.Added,
				},
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-2", Namespace: "default"}},
					Action: rulebindingmanager.Added,
				},
			},
			b: []rulebindingmanager.RuleBindingNotify{
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-2", Namespace: "default"}},
					Action: rulebindingmanager.Removed,
				},
			},
			want: []rulebindingmanager.RuleBindingNotify{
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-1", Namespace: "default"}},
					Action: rulebindingmanager.Added,
				},
			},
		},
		{
			name: "Test with overlapping slices - 2",
			a: []rulebindingmanager.RuleBindingNotify{
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-2", Namespace: "default"}},
					Action: rulebindingmanager.Added,
				},
			},
			b: []rulebindingmanager.RuleBindingNotify{
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-1", Namespace: "default"}},
					Action: rulebindingmanager.Removed,
				},
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-2", Namespace: "default"}},
					Action: rulebindingmanager.Removed,
				},
			},
			want: []rulebindingmanager.RuleBindingNotify{
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-1", Namespace: "default"}},
					Action: rulebindingmanager.Removed,
				},
			},
		},
		{
			name: "Test all overlapping slices",
			a: []rulebindingmanager.RuleBindingNotify{
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-1", Namespace: "default"}},
					Action: rulebindingmanager.Added,
				},
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-2", Namespace: "default"}},
					Action: rulebindingmanager.Added,
				},
			},
			b: []rulebindingmanager.RuleBindingNotify{
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-1", Namespace: "default"}},
					Action: rulebindingmanager.Removed,
				},
				{
					Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-2", Namespace: "default"}},
					Action: rulebindingmanager.Removed,
				},
			},
			want: []rulebindingmanager.RuleBindingNotify{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := diff(tt.a, tt.b)
			var gotL []string
			for _, v := range got {
				gotL = append(gotL, fmt.Sprintf("%s-%s-%d", v.Pod.Namespace, v.Pod.Name, v.Action))
			}
			var wantL []string
			for _, v := range tt.want {
				wantL = append(wantL, fmt.Sprintf("%s-%s-%d", v.Pod.Namespace, v.Pod.Name, v.Action))
			}
			slices.Sort(gotL)
			slices.Sort(wantL)

			assert.Equal(t, wantL, gotL)
		})
	}
}
