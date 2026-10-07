package prefilter

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type observedJSON struct {
	calls *int
	data  string
}

func (v observedJSON) MarshalJSON() ([]byte, error) {
	(*v.calls)++
	return []byte(v.data), nil
}

func TestParseWithDefaultsUnknownStateStillValidated(t *testing.T) {
	for _, data := range []string{`{"nested":"value"}`, `{`} {
		t.Run(data, func(t *testing.T) {
			calls := 0
			state := map[string]any{"custom_state": observedJSON{&calls, data}}
			for range 2 {
				require.Nil(t, ParseWithDefaults(state, nil))
			}
			require.Equal(t, 2, calls, "unknown state must still be marshaled and validated")
			state["ports"] = []uint16{443}
			got := ParseWithDefaults(state, nil)
			if json.Valid([]byte(data)) {
				require.NotNil(t, got)
				require.Equal(t, []uint16{443}, got.Ports)
			} else {
				require.Nil(t, got, "invalid unknown value must still reject parameters")
			}
		})
	}
}

func TestParseWithDefaultsCaseFoldedKeys(t *testing.T) {
	for _, key := range []string{"ports", "Ports", "PORTS", "portſ"} {
		t.Run(key, func(t *testing.T) {
			got := ParseWithDefaults(map[string]any{"custom_state": "value"}, map[string]any{key: []uint16{443}})
			require.NotNil(t, got)
			require.Equal(t, []uint16{443}, got.Ports)
			require.Nil(t, ParseWithDefaults(map[string]any{key: "malformed"}, nil))
		})
	}
}

func TestParseWithDefaultsAllFilterKeys(t *testing.T) {
	for _, tc := range []struct {
		key   string
		value any
	}{
		{"ignorePrefixes", []string{"/tmp"}},
		{"includePrefixes", []string{"/tmp"}},
		{"ports", []uint16{443}},
		{"direction", "inbound"},
		{"methods", []string{"GET"}},
		{"excludeProcesses", []map[string]string{{"name": "process", "path": "/bin/process"}}},
		{"excludeParentProcesses", []map[string]string{{"name": "parent", "path": "/bin/parent"}}},
	} {
		for _, key := range []string{tc.key, strings.ToUpper(tc.key), strings.ToUpper(tc.key[:1]) + tc.key[1:]} {
			t.Run(key, func(t *testing.T) {
				got := ParseWithDefaults(map[string]any{"custom_state": "value", key: tc.value}, nil)
				require.NotNil(t, got)
			})
		}
	}
}

func TestPrefilterKeyCheckCoversDecoderFields(t *testing.T) {
	// Keep the fast path in sync when rawParams gains a new decoded field.
	decoded := reflect.TypeFor[rawParams]()
	for i := range decoded.NumField() {
		key := strings.Split(decoded.Field(i).Tag.Get("json"), ",")[0]
		require.NotEmpty(t, key)
		require.True(t, hasPrefilterKey(map[string]any{key: nil}), key)
		require.True(t, hasPrefilterKey(map[string]any{strings.ToUpper(key): nil}), key)
	}
}

func TestParseWithDefaultsObservesStateChanges(t *testing.T) {
	state := map[string]any{"custom_state": "value"}
	require.Nil(t, ParseWithDefaults(state, nil))
	state["ports"] = []uint16{443}
	got := ParseWithDefaults(state, nil)
	require.NotNil(t, got)
	require.Equal(t, []uint16{443}, got.Ports)
	got = ParseWithDefaults(state, map[string]any{"ports": []uint16{8443}})
	require.Equal(t, []uint16{8443}, got.Ports)
	delete(state, "ports")
	require.Nil(t, ParseWithDefaults(state, nil))
}

var parsedStateSink *Params

func BenchmarkParseRuleState(b *testing.B) {
	for _, tc := range []struct {
		name  string
		state map[string]any
	}{
		{"nil", nil},
		{"nonfilter", map[string]any{"custom_state": "value"}},
		{"nonfilter_nested", map[string]any{"custom_state": map[string]any{"ports": []uint16{443}, "name": "value"}}},
		{"filter", map[string]any{"ports": []uint16{443}}},
		{"filter_casefold", map[string]any{"PORTS": []uint16{443}}},
		{"filter_multiple", map[string]any{"ports": []uint16{443}, "methods": []string{"GET"}, "direction": "inbound"}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				parsedStateSink = ParseWithDefaults(tc.state, nil)
			}
		})
	}
}
