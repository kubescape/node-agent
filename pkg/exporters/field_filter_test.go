package exporters

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEventFieldFilter_NilConfig(t *testing.T) {
	f := NewEventFieldFilter(nil)
	assert.Nil(t, f)
}

func TestNewEventFieldFilter_EmptyConfig(t *testing.T) {
	f := NewEventFieldFilter(&EventFieldFilterConfig{})
	assert.Nil(t, f)
}

func TestNewEventFieldFilter_WithAllowList(t *testing.T) {
	f := NewEventFieldFilter(&EventFieldFilterConfig{
		AllowList: []string{"message", "ruleID"},
	})
	assert.NotNil(t, f)
	assert.True(t, f.useAllow)
}

func TestNewEventFieldFilter_WithDenyList(t *testing.T) {
	f := NewEventFieldFilter(&EventFieldFilterConfig{
		DenyList: []string{"processTree"},
	})
	assert.NotNil(t, f)
	assert.False(t, f.useAllow)
}

func TestFilterJSON_AllowListNestedField(t *testing.T) {
	f := NewEventFieldFilter(&EventFieldFilterConfig{
		AllowList: []string{"kind", "spec.alerts"},
	})

	input := map[string]any{
		"kind": "RuntimeAlerts",
		"spec": map[string]any{
			"alerts":        []any{"alert1"},
			"processTree":   map[string]any{"pid": 1234},
			"cloudMetadata": map[string]any{"region": "us-east-1"},
		},
	}
	data, _ := json.Marshal(input)

	result, err := f.FilterJSON(data)
	require.NoError(t, err)

	var output map[string]any
	err = json.Unmarshal(result, &output)
	require.NoError(t, err)

	assert.Equal(t, "RuntimeAlerts", output["kind"])
	spec := output["spec"].(map[string]any)
	assert.NotNil(t, spec["alerts"])
	assert.Nil(t, spec["processTree"])
	assert.Nil(t, spec["cloudMetadata"])
	assert.Nil(t, output["apiVersion"])
}

func TestFilterJSON_AllowList(t *testing.T) {
	f := NewEventFieldFilter(&EventFieldFilterConfig{
		AllowList: []string{"message", "ruleID"},
	})

	input := map[string]any{
		"message":     "Unexpected process launched",
		"ruleID":      "R0001",
		"processTree": map[string]any{"pid": 1234, "comm": "bash"},
		"k8sDetails":  map[string]any{"namespace": "default"},
	}
	data, _ := json.Marshal(input)

	result, err := f.FilterJSON(data)
	require.NoError(t, err)

	var output map[string]any
	err = json.Unmarshal(result, &output)
	require.NoError(t, err)

	assert.Equal(t, "Unexpected process launched", output["message"])
	assert.Equal(t, "R0001", output["ruleID"])
	assert.Nil(t, output["processTree"])
	assert.Nil(t, output["k8sDetails"])
}

func TestFilterJSON_DenyList(t *testing.T) {
	f := NewEventFieldFilter(&EventFieldFilterConfig{
		DenyList: []string{"processTree", "k8sDetails"},
	})

	input := map[string]any{
		"message":     "Unexpected process launched",
		"ruleID":      "R0001",
		"processTree": map[string]any{"pid": 1234},
		"k8sDetails":  map[string]any{"namespace": "default"},
	}
	data, _ := json.Marshal(input)

	result, err := f.FilterJSON(data)
	require.NoError(t, err)

	var output map[string]any
	err = json.Unmarshal(result, &output)
	require.NoError(t, err)

	assert.Equal(t, "Unexpected process launched", output["message"])
	assert.Equal(t, "R0001", output["ruleID"])
	assert.Nil(t, output["processTree"])
	assert.Nil(t, output["k8sDetails"])
}

func TestFilterJSON_DenyListNestedField(t *testing.T) {
	f := NewEventFieldFilter(&EventFieldFilterConfig{
		DenyList: []string{"spec.processTree"},
	})

	input := map[string]any{
		"kind": "RuntimeAlerts",
		"spec": map[string]any{
			"alerts":      []interface{}{"alert1"},
			"processTree": map[string]any{"pid": 1234},
		},
	}
	data, _ := json.Marshal(input)

	result, err := f.FilterJSON(data)
	require.NoError(t, err)

	var output map[string]any
	err = json.Unmarshal(result, &output)
	require.NoError(t, err)

	assert.Equal(t, "RuntimeAlerts", output["kind"])
	spec := output["spec"].(map[string]any)
	assert.NotNil(t, spec["alerts"])
	assert.Nil(t, spec["processTree"])
}

func TestFilterJSON_AllowListTakesPrecedence(t *testing.T) {
	// "ruleID" is in BOTH lists. If allowList takes precedence, it must be kept
	// (allowList wins, denyList is ignored entirely). If denyList were also applied,
	// "ruleID" would be removed, proving precedence didn't hold.
	f := NewEventFieldFilter(&EventFieldFilterConfig{
		AllowList: []string{"message", "ruleID"},
		DenyList:  []string{"ruleID"},
	})

	input := map[string]any{
		"message": "test",
		"ruleID":  "R0001",
		"extra":   "data",
	}
	data, _ := json.Marshal(input)

	result, err := f.FilterJSON(data)
	require.NoError(t, err)

	var output map[string]any
	err = json.Unmarshal(result, &output)
	require.NoError(t, err)

	assert.Equal(t, "test", output["message"])
	assert.Equal(t, "R0001", output["ruleID"], "ruleID kept because allowList takes precedence over denyList")
	assert.Nil(t, output["extra"], "extra dropped (not in allowList)")
}

func TestFilterJSON_DenyListSliceField(t *testing.T) {
	f := NewEventFieldFilter(&EventFieldFilterConfig{
		DenyList: []string{"spec.alerts.ruleID"},
	})

	input := map[string]any{
		"kind": "RuntimeAlerts",
		"spec": map[string]any{
			"alerts": []any{
				map[string]any{"ruleID": "R0001", "message": "alert 1"},
				map[string]any{"ruleID": "R0002", "message": "alert 2"},
			},
			"processTree": map[string]any{"pid": 1234},
		},
	}
	data, _ := json.Marshal(input)

	result, err := f.FilterJSON(data)
	require.NoError(t, err)

	var output map[string]any
	err = json.Unmarshal(result, &output)
	require.NoError(t, err)

	spec := output["spec"].(map[string]any)
	alerts := spec["alerts"].([]any)
	require.Len(t, alerts, 2)

	// ruleID removed from each alert, message kept
	for _, a := range alerts {
		alert := a.(map[string]any)
		assert.Nil(t, alert["ruleID"])
		assert.NotNil(t, alert["message"])
	}
	// processTree unaffected
	assert.NotNil(t, spec["processTree"])
}

func TestFilterJSON_AllowListSliceField(t *testing.T) {
	f := NewEventFieldFilter(&EventFieldFilterConfig{
		AllowList: []string{"kind", "spec.alerts.message"},
	})

	input := map[string]any{
		"kind": "RuntimeAlerts",
		"spec": map[string]any{
			"alerts": []any{
				map[string]any{"ruleID": "R0001", "message": "alert 1", "severity": 5},
				map[string]any{"ruleID": "R0002", "message": "alert 2", "severity": 3},
			},
			"processTree":   map[string]any{"pid": 1234},
			"cloudMetadata": map[string]any{"region": "us-east-1"},
		},
	}
	data, _ := json.Marshal(input)

	result, err := f.FilterJSON(data)
	require.NoError(t, err)

	var output map[string]any
	err = json.Unmarshal(result, &output)
	require.NoError(t, err)

	assert.Equal(t, "RuntimeAlerts", output["kind"])
	spec := output["spec"].(map[string]any)
	alerts := spec["alerts"].([]any)
	require.Len(t, alerts, 2)

	// only message kept in each alert
	for _, a := range alerts {
		alert := a.(map[string]any)
		assert.NotNil(t, alert["message"])
		assert.Nil(t, alert["ruleID"])
		assert.Nil(t, alert["severity"])
	}
	// processTree and cloudMetadata dropped
	assert.Nil(t, spec["processTree"])
	assert.Nil(t, spec["cloudMetadata"])
}

func TestFilterJSON_InvalidJSON_ReturnsError(t *testing.T) {
	f := NewEventFieldFilter(&EventFieldFilterConfig{
		DenyList: []string{"spec.processTree"},
	})

	_, err := f.FilterJSON([]byte(`{not valid json`))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "field filter: failed to unmarshal")
}

func TestFilterJSON_AllowListSliceField_OmitsEmptyItems(t *testing.T) {
	// When an allow list targets a sub-field inside a slice, items that
	// have none of the allowed fields should be omitted from the output.
	f := NewEventFieldFilter(&EventFieldFilterConfig{
		AllowList: []string{"kind", "spec.alerts.message"},
	})

	input := map[string]any{
		"kind": "RuntimeAlerts",
		"spec": map[string]any{
			"alerts": []any{
				map[string]any{"ruleID": "R0001", "message": "alert 1"},
				map[string]any{"ruleID": "R0002", "severity": 5}, // no "message" → empty after filter
				map[string]any{"message": "alert 3", "severity": 3},
			},
		},
	}
	data, _ := json.Marshal(input)

	result, err := f.FilterJSON(data)
	require.NoError(t, err)

	var output map[string]any
	err = json.Unmarshal(result, &output)
	require.NoError(t, err)

	spec := output["spec"].(map[string]any)
	alerts := spec["alerts"].([]any)

	// Second item had no "message", so it's omitted
	require.Len(t, alerts, 2)
	assert.Equal(t, "alert 1", alerts[0].(map[string]any)["message"])
	assert.Equal(t, "alert 3", alerts[1].(map[string]any)["message"])
}

func TestFilterJSON_NoHTMLEscaping(t *testing.T) {
	// json.Marshal escapes <, >, & but our filter should not
	f := NewEventFieldFilter(&EventFieldFilterConfig{
		DenyList: []string{"extra"},
	})

	input := map[string]any{
		"message": "process > limit & value < threshold",
		"extra":   "removed",
	}
	data, _ := json.Marshal(input)

	result, err := f.FilterJSON(data)
	require.NoError(t, err)

	// The output should contain literal <, >, & not escaped unicode
	assert.Contains(t, string(result), `process > limit & value < threshold`)
	assert.NotContains(t, string(result), `\u003c`)
	assert.NotContains(t, string(result), `\u003e`)
	assert.NotContains(t, string(result), `\u0026`)
}

func TestFilterJSON_AllowList_ScalarLeaf_MapToScalar(t *testing.T) {
	// Allow path ends at a scalar inside a nested map — must be kept, not silently dropped.
	f := NewEventFieldFilter(&EventFieldFilterConfig{
		AllowList: []string{"spec.processTree.pid"},
	})

	input := map[string]any{
		"spec": map[string]any{
			"processTree": map[string]any{
				"pid":  1234,
				"comm": "sh",
			},
		},
	}
	data, _ := json.Marshal(input)

	result, err := f.FilterJSON(data)
	require.NoError(t, err)

	var output map[string]any
	require.NoError(t, json.Unmarshal(result, &output))

	pt := output["spec"].(map[string]any)["processTree"].(map[string]any)
	assert.NotNil(t, pt["pid"], "scalar pid kept")
	assert.Nil(t, pt["comm"], "comm dropped")
}

func TestFilterJSON_AllowList_ScalarLeaf_InsideSlice(t *testing.T) {
	// Allow path ends at a scalar inside each slice element — must be kept.
	f := NewEventFieldFilter(&EventFieldFilterConfig{
		AllowList: []string{"spec.alerts.severity"},
	})

	input := map[string]any{
		"spec": map[string]any{
			"alerts": []any{
				map[string]any{"ruleID": "R0001", "message": "msg1", "severity": 5},
				map[string]any{"ruleID": "R0002", "message": "msg2", "severity": 7},
			},
		},
	}
	data, _ := json.Marshal(input)

	result, err := f.FilterJSON(data)
	require.NoError(t, err)

	var output map[string]any
	require.NoError(t, json.Unmarshal(result, &output))

	alerts := output["spec"].(map[string]any)["alerts"].([]any)
	require.Len(t, alerts, 2)
	for i, a := range alerts {
		alert := a.(map[string]any)
		assert.NotNil(t, alert["severity"], "alert[%d]: severity kept", i)
		assert.Nil(t, alert["ruleID"], "alert[%d]: ruleID dropped", i)
		assert.Nil(t, alert["message"], "alert[%d]: message dropped", i)
	}
}
