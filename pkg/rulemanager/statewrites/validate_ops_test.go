package statewrites

import (
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidate_Operations(t *testing.T) {
	cases := []struct {
		name    string
		mut     func(*armotypes.StateWrite)
		wantOp  Op
		wantErr string
	}{
		{"neither field is a set", func(*armotypes.StateWrite) {}, OpSet, ""},
		{"value without the new fields is a set", func(w *armotypes.StateWrite) { w.Value = map[string]any{"a": "event.comm"} }, OpSet, ""},
		{"increment 1", func(w *armotypes.StateWrite) { w.Increment = 1 }, OpIncrement, ""},
		{"clear with ttl", func(w *armotypes.StateWrite) { w.Clear = true }, OpClear, ""},
		{"clear without ttl", func(w *armotypes.StateWrite) { w.Clear = true; w.TTL = "" }, OpClear, ""},
		{"increment 2", func(w *armotypes.StateWrite) { w.Increment = 2 }, 0, "increment must be 1"},
		{"increment -1", func(w *armotypes.StateWrite) { w.Increment = -1 }, 0, "increment must be 1"},
		{"increment with clear", func(w *armotypes.StateWrite) { w.Increment = 1; w.Clear = true }, 0, "exactly one of"},
		{"value with increment", func(w *armotypes.StateWrite) { w.Increment = 1; w.Value = map[string]any{"a": "event.comm"} }, 0, "exactly one of"},
		{"value with clear", func(w *armotypes.StateWrite) { w.Clear = true; w.Value = map[string]any{"a": "event.comm"} }, 0, "exactly one of"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := base()
			tc.mut(&w)
			c, err := Validate(w, "R1213", 30*time.Minute)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantOp, c.Op)
		})
	}
}

func TestValidate_IncrementStillRequiresTTL(t *testing.T) {
	w := base()
	w.Increment = 1
	w.TTL = ""
	_, err := Validate(w, "R1213", 30*time.Minute)
	require.Error(t, err, "a counter with no window is a counter that never resets")
}

func TestValidateAll_RejectsSetAndIncrementOnOneName(t *testing.T) {
	set := base()
	inc := base()
	inc.Increment = 1
	_, _, err := ValidateAll([]armotypes.StateWrite{set, inc}, "R1213", 30*time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "both a set and an increment")
}

func TestValidateAll_AllowsClearWithIncrement(t *testing.T) {
	inc := base()
	inc.Increment = 1
	clr := base()
	clr.Clear = true
	compiled, scopeOf, err := ValidateAll([]armotypes.StateWrite{inc, clr}, "R1213", 30*time.Minute)
	require.NoError(t, err)
	assert.Len(t, compiled, 2)
	assert.Equal(t, armotypes.StateScopeContainer, scopeOf["mount_exec"])
}

func TestValidateAll_AllowsClearWithSet(t *testing.T) {
	set := base()
	clr := base()
	clr.Clear = true
	_, _, err := ValidateAll([]armotypes.StateWrite{set, clr}, "R1213", 30*time.Minute)
	require.NoError(t, err)
}
