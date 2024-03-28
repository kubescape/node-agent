package cache

import (
	"context"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/rulebindingmanager/types/v1"
	ruleenginev1 "node-agent/pkg/ruleengine/v1"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func NewCacheMock(nodeName string) *RBCache {
	return &RBCache{
		nodeName:         nodeName,
		k8sClient:        &k8sclient.K8sClientMock{},
		ruleCreator:      ruleenginev1.NewRuleCreator(),
		globalRBNames:    mapset.NewSet[string](),
		podToRBNames:     maps.SafeMap[string, mapset.Set[string]]{},
		rbNameToPodNames: maps.SafeMap[string, mapset.Set[string]]{},
	}
}
func TestRuntimeObjAddHandler(t *testing.T) {
	type rules struct {
		ruleName string
		ruleID   string
	}
	type args struct {
		c   *RBCache
		pod *corev1.Pod
		rb  []types.RuntimeAlertRuleBinding
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
				rb: []types.RuntimeAlertRuleBinding{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "testRB",
							Namespace: "testNamespace",
						},
						Spec: types.RuntimeAlertRuleBindingSpec{
							PodSelector: metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": "testPod",
								},
							},
							Rules: []types.RuntimeAlertRuleBindingRule{
								{
									RuleName: "Unexpected process launched",
									RuleID:   "R0001",
								},
							},
						},
					},
				},
			},
			expectedRules: []rules{
				{
					ruleName: "Unexpected process launched",
					ruleID:   "R0001",
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
				rb: []types.RuntimeAlertRuleBinding{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "testRB",
							Namespace: "testNamespace",
						},
						Spec: types.RuntimeAlertRuleBindingSpec{
							PodSelector: metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{
										Key:      "app",
										Operator: metav1.LabelSelectorOpIn,
										Values:   []string{"testPod"},
									},
								},
							},
							Rules: []types.RuntimeAlertRuleBindingRule{
								{
									RuleName: "Unexpected process launched",
									RuleID:   "R0001",
								},
							},
						},
					},
				},
			},
			expectedRules: []rules{
				{
					ruleName: "Unexpected process launched",
					ruleID:   "R0001",
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
				rb: []types.RuntimeAlertRuleBinding{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "testRB",
							Namespace: "testNamespace",
						},
						Spec: types.RuntimeAlertRuleBindingSpec{
							PodSelector: metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": "testPod1",
								},
							},
							Rules: []types.RuntimeAlertRuleBindingRule{
								{
									RuleName: "Unexpected process launched",
									RuleID:   "R0001",
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
				assert.Equal(t, tt.expectedRules[i].ruleName, r[i].Name())
				assert.Equal(t, tt.expectedRules[i].ruleID, r[i].ID())

			}
		})

	}
}
