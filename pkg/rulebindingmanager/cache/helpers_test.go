package cache

import (
	"testing"

	typesv1 "github.com/kubescape/node-agent/pkg/rulebindingmanager/types/v1"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestResourcesToWatch(t *testing.T) {
	tests := []struct {
		name     string
		nodeName string
	}{
		{
			name:     "Test with valid node name",
			nodeName: "node-1",
		},
		{
			name:     "Test with empty node name",
			nodeName: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resourcesToWatch(tt.nodeName)

			assert.Equal(t, 2, len(result))

			podResource := result[0]
			assert.Equal(t, "v1", podResource.GroupVersionResource().Version)
			assert.Equal(t, "pods", podResource.GroupVersionResource().Resource)
			assert.Equal(t, "spec.nodeName="+tt.nodeName, podResource.ListOptions().FieldSelector)

			rbResource := result[1]
			assert.Equal(t, typesv1.RuleBindingAlertGvr, rbResource.GroupVersionResource())
			assert.Equal(t, metav1.ListOptions{}, rbResource.ListOptions())
		})
	}
}

func TestUnstructuredToRuleBinding(t *testing.T) {
	tests := []struct {
		obj     *unstructured.Unstructured
		name    string
		wantErr bool
	}{
		{
			name: "Test with valid rule binding",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "RuntimeAlertRuleBinding",
					"metadata": map[string]interface{}{
						"name":      "rule-1",
						"namespace": "default",
					},
					"spec": map[string]interface{}{
						"ruleName": "rule-1",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test with invalid rule binding",
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
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := unstructuredToRuleBinding(tt.obj)
			if (err != nil) != tt.wantErr {
				t.Errorf("unstructuredToRuleBinding() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestUniqueName(t *testing.T) {
	tests := []struct {
		name     string
		obj      metav1.Object
		expected string
	}{
		{
			name: "Pod with valid namespace and name",
			obj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod-1",
					Namespace: "default",
				},
			},
			expected: "default/pod-1",
		},
		{
			name: "Pod with empty namespace",
			obj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod-1",
					Namespace: "",
				},
			},
			expected: "/pod-1",
		},
		{
			name: "Pod with empty name",
			obj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "",
					Namespace: "default",
				},
			},
			expected: "default/",
		},
		{
			name: "Pod with empty namespace and name",
			obj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "",
					Namespace: "",
				},
			},
			expected: "/",
		},
		{
			name: "RuntimeAlertRuleBinding with valid namespace and name",
			obj: &typesv1.RuntimeAlertRuleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name-1",
					Namespace: "default",
				},
			},
			expected: "default/name-1",
		},
		{
			name: "RuntimeAlertRuleBinding with empty namespace",
			obj: &typesv1.RuntimeAlertRuleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name-1",
					Namespace: "",
				},
			},
			expected: "/name-1",
		},
		{
			name: "RuntimeAlertRuleBinding with empty name",
			obj: &typesv1.RuntimeAlertRuleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "",
					Namespace: "default",
				},
			},
			expected: "default/",
		},
		{
			name: "RuntimeAlertRuleBinding with empty namespace and name",
			obj: &typesv1.RuntimeAlertRuleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "",
					Namespace: "",
				},
			},
			expected: "/",
		},
		{
			name: "Unstructured with valid namespace and name",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"name":      "name-1",
						"namespace": "default",
					},
				},
			},
			expected: "default/name-1",
		},
		{
			name: "Unstructured with empty namespace",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"name":      "name-1",
						"namespace": "",
					},
				},
			},
			expected: "/name-1",
		},
		{
			name: "Unstructured with empty name",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"name":      "",
						"namespace": "default",
					},
				},
			},
			expected: "default/",
		},
		{
			name: "Unstructured with empty namespace and name",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"name":      "",
						"namespace": "",
					},
				},
			},
			expected: "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := uniqueName(tt.obj)
			assert.Equal(t, tt.expected, result)
		})
	}
}
