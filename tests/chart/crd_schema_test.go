package chart

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	structuralschema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	schemacel "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel"
	apiextvalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"sigs.k8s.io/yaml"
)

// crdSchema loads the Rules CRD exactly as the chart ships it and returns a
// validator that applies both the OpenAPI schema and its x-kubernetes-validations
// CEL rules, which is what the API server does on admission.
func crdSchema(t *testing.T) func(obj map[string]any) field.ErrorList {
	t.Helper()
	raw, err := os.ReadFile("crds/rules.crd.yaml")
	require.NoError(t, err)
	var crd apiextensionsv1.CustomResourceDefinition
	require.NoError(t, yaml.Unmarshal(raw, &crd))
	require.Len(t, crd.Spec.Versions, 1)

	internal := &apiextensions.JSONSchemaProps{}
	require.NoError(t, apiextensionsv1.Convert_v1_JSONSchemaProps_To_apiextensions_JSONSchemaProps(
		crd.Spec.Versions[0].Schema.OpenAPIV3Schema, internal, nil))

	openapi, _, err := apiextvalidation.NewSchemaValidator(internal)
	require.NoError(t, err)
	structural, err := structuralschema.NewStructural(internal)
	require.NoError(t, err)
	celValidator := schemacel.NewValidator(structural, true, celconfig.PerCallLimit)
	require.NotNil(t, celValidator, "the CRD declares no x-kubernetes-validations")

	return func(obj map[string]any) field.ErrorList {
		errs := apiextvalidation.ValidateCustomResource(nil, obj, openapi)
		celErrs, _ := celValidator.Validate(context.Background(), nil, structural, obj, nil, celconfig.RuntimeCELCostBudget)
		return append(errs, celErrs...)
	}
}

func rulesObject(write map[string]any) map[string]any {
	return map[string]any{
		"apiVersion": "kubescape.io/v1",
		"kind":       "Rules",
		"metadata":   map[string]any{"name": "t", "namespace": "kubescape"},
		"spec": map[string]any{
			"rules": []any{map[string]any{
				"name":           "t",
				"enabled":        true,
				"id":             "R9999",
				"description":    "schema fixture",
				"supportPolicy":  false,
				"isTriggerAlert": true,
				"mitreTactic":    "TA0002",
				"mitreTechnique": "T1059",
				"expressions": map[string]any{
					"message":  "'m'",
					"uniqueId": "'u'",
					"ruleExpression": []any{map[string]any{
						"eventType": "exec", "expression": "true",
					}},
				},
				"profileDependency": int64(2),
				"severity":          int64(1),
				"stateWrites":       []any{write},
			}},
		},
	}
}

// Matches the runtime contract in pkg/rulemanager/statewrites: a clear has no
// window of its own, so ttl is optional on it and required on set and
// increment. Admission must agree, or a documented, runtime-valid clause is
// rejected by kubectl apply.
func TestRulesCRD_TTLRequiredExceptOnClear(t *testing.T) {
	validate := crdSchema(t)
	base := func() map[string]any {
		return map[string]any{"eventType": "exec", "scope": "container", "name": "n", "key": "string(event.pid)"}
	}

	t.Run("clear without ttl is accepted", func(t *testing.T) {
		w := base()
		w["clear"] = true
		require.Empty(t, validate(rulesObject(w)))
	})
	t.Run("clear with ttl is accepted", func(t *testing.T) {
		w := base()
		w["clear"] = true
		w["ttl"] = "1m"
		require.Empty(t, validate(rulesObject(w)))
	})
	t.Run("set without ttl is rejected", func(t *testing.T) {
		w := base()
		errs := validate(rulesObject(w))
		require.NotEmpty(t, errs)
		require.Contains(t, strings.ToLower(errs.ToAggregate().Error()), "ttl")
	})
	t.Run("increment without ttl is rejected", func(t *testing.T) {
		w := base()
		w["increment"] = int64(1)
		errs := validate(rulesObject(w))
		require.NotEmpty(t, errs)
		require.Contains(t, strings.ToLower(errs.ToAggregate().Error()), "ttl")
	})
	t.Run("set and increment with ttl are accepted", func(t *testing.T) {
		w := base()
		w["ttl"] = "5m"
		require.Empty(t, validate(rulesObject(w)))
		w["increment"] = int64(1)
		require.Empty(t, validate(rulesObject(w)))
	})
}
