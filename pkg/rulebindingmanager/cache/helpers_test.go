package cache

import (
	typesv1 "node-agent/pkg/rulebindingmanager/types/v1"
	"testing"

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

func TestUniqueName(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		rName     string
		expected  string
	}{
		{
			name:      "Test with valid namespace and name",
			namespace: "default",
			rName:     "name-1",
			expected:  "default/name-1",
		},
		{
			name:      "Test with empty namespace",
			namespace: "",
			rName:     "name-1",
			expected:  "/name-1",
		},
		{
			name:      "Test with empty name",
			namespace: "default",
			rName:     "",
			expected:  "default/",
		},
		{
			name:      "Test with empty namespace and name",
			namespace: "",
			rName:     "",
			expected:  "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := uniqueName(tt.namespace, tt.rName)
			assert.Equal(t, tt.expected, result)
		})
	}
}
func TestUnstructuredToPod(t *testing.T) {
	tests := []struct {
		obj     *unstructured.Unstructured
		name    string
		wantErr bool
	}{
		{
			name: "Test with valid pod",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "Pod",
					"metadata": map[string]interface{}{
						"name":      "pod-1",
						"namespace": "default",
					},
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "container-1",
								"image": "image-1",
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test with invalid pod",
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
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := unstructuredToPod(tt.obj)
			if (err != nil) != tt.wantErr {
				t.Errorf("unstructuredToPod() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
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
func TestUnstructuredUniqueName(t *testing.T) {
	tests := []struct {
		name     string
		obj      *unstructured.Unstructured
		expected string
	}{
		{
			name: "Test with valid namespace and name",
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
			name: "Test with empty namespace",
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
			name: "Test with empty name",
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
			name: "Test with empty namespace and name",
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
			result := unstructuredUniqueName(tt.obj)
			assert.Equal(t, tt.expected, result)
		})
	}
}
func TestRbUniqueName(t *testing.T) {
	tests := []struct {
		name     string
		rb       *typesv1.RuntimeAlertRuleBinding
		expected string
	}{
		{
			name: "Test with valid namespace and name",
			rb: &typesv1.RuntimeAlertRuleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name-1",
					Namespace: "default",
				},
			},
			expected: "default/name-1",
		},
		{
			name: "Test with empty namespace",
			rb: &typesv1.RuntimeAlertRuleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name-1",
					Namespace: "",
				},
			},
			expected: "/name-1",
		},
		{
			name: "Test with empty name",
			rb: &typesv1.RuntimeAlertRuleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "",
					Namespace: "default",
				},
			},
			expected: "default/",
		},
		{
			name: "Test with empty namespace and name",
			rb: &typesv1.RuntimeAlertRuleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "",
					Namespace: "",
				},
			},
			expected: "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rbUniqueName(tt.rb)
			assert.Equal(t, tt.expected, result)
		})
	}
}
func TestPodUniqueName(t *testing.T) {
	tests := []struct {
		name     string
		pod      *corev1.Pod
		expected string
	}{
		{
			name: "Test with valid namespace and name",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod-1",
					Namespace: "default",
				},
			},
			expected: "default/pod-1",
		},
		{
			name: "Test with empty namespace",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod-1",
					Namespace: "",
				},
			},
			expected: "/pod-1",
		},
		{
			name: "Test with empty name",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "",
					Namespace: "default",
				},
			},
			expected: "default/",
		},
		{
			name: "Test with empty namespace and name",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "",
					Namespace: "",
				},
			},
			expected: "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := podUniqueName(tt.pod)
			assert.Equal(t, tt.expected, result)
		})
	}
}
