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
			"alerts":      []any{"alert1"},
			"processTree": map[string]any{"pid": 1234},
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
	f := NewEventFieldFilter(&EventFieldFilterConfig{
		AllowList: []string{"message"},
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
	assert.Nil(t, output["ruleID"])
	assert.Nil(t, output["extra"])
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
