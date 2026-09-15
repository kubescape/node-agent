package ruleswatcher

import (
	"os"
	"testing"

	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

func TestUnstructuredToRules_ProfileDataRequired(t *testing.T) {
	t.Run("valid profileDataRequired", func(t *testing.T) {
		obj := &unstructured.Unstructured{
			Object: map[string]any{
				"spec": map[string]any{
					"rules": []any{
						map[string]any{
							"id": "R0001",
							"profileDataRequired": map[string]any{
								"opens": "all",
								"execs": []any{
									map[string]any{"exact": "/bin/sh"},
								},
							},
						},
					},
				},
			},
		}

		rules, err := unstructuredToRules(obj)
		require.NoError(t, err)
		require.NotNil(t, rules.Spec.Rules[0].ProfileDataRequired)
		require.NotNil(t, rules.Spec.Rules[0].ProfileDataRequired.Opens)
		assert.True(t, rules.Spec.Rules[0].ProfileDataRequired.Opens.All)
		require.NotNil(t, rules.Spec.Rules[0].ProfileDataRequired.Execs)
		require.Len(t, rules.Spec.Rules[0].ProfileDataRequired.Execs.Patterns, 1)
		assert.Equal(t, "/bin/sh", rules.Spec.Rules[0].ProfileDataRequired.Execs.Patterns[0].Exact)
	})

	t.Run("rejects unknown surface key", func(t *testing.T) {
		obj := &unstructured.Unstructured{
			Object: map[string]any{
				"spec": map[string]any{
					"rules": []any{
						map[string]any{
							"id": "R0001",
							"profileDataRequired": map[string]any{
								"unknownSurface": "all",
							},
						},
					},
				},
			},
		}

		_, err := unstructuredToRules(obj)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `unknown field "unknownSurface"`)
	})

	t.Run("rejects unknown pattern key", func(t *testing.T) {
		obj := &unstructured.Unstructured{
			Object: map[string]any{
				"spec": map[string]any{
					"rules": []any{
						map[string]any{
							"id": "R0001",
							"profileDataRequired": map[string]any{
								"opens": []any{
									map[string]any{"exct": "/bin/sh"},
								},
							},
						},
					},
				},
			},
		}

		_, err := unstructuredToRules(obj)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `unknown field "exct"`)
	})

	t.Run("rejects invalid pattern object with multiple fields", func(t *testing.T) {
		obj := &unstructured.Unstructured{
			Object: map[string]any{
				"spec": map[string]any{
					"rules": []any{
						map[string]any{
							"id": "R0001",
							"profileDataRequired": map[string]any{
								"opens": []any{
									map[string]any{"exact": "/bin/sh", "prefix": "/usr/"},
								},
							},
						},
					},
				},
			},
		}

		_, err := unstructuredToRules(obj)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exactly one of {exact, prefix, suffix, contains} must be set")
	})
}

func TestUnstructuredToRules_DefaultRulesYAML(t *testing.T) {
	data, err := os.ReadFile("../../../tests/chart/templates/node-agent/default-rules.yaml")
	require.NoError(t, err)

	var objMap map[string]any
	err = yaml.Unmarshal(data, &objMap)
	require.NoError(t, err)

	obj := &unstructured.Unstructured{Object: objMap}
	rules, err := unstructuredToRules(obj)
	require.NoError(t, err)
	require.NotEmpty(t, rules.Spec.Rules)

	var r0001 *typesv1.Rule
	for i := range rules.Spec.Rules {
		if rules.Spec.Rules[i].ID == "R0001" {
			r0001 = &rules.Spec.Rules[i]
			break
		}
	}
	require.NotNil(t, r0001)
	require.NotNil(t, r0001.ProfileDataRequired)
	require.NotNil(t, r0001.ProfileDataRequired.Execs)
	assert.True(t, r0001.ProfileDataRequired.Execs.All)
}

