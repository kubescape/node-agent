package v1

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMergeMaps(t *testing.T) {
	tests := []struct {
		name     string
		existing map[string]string
		new      map[string]string
		expected map[string]string
	}{
		{
			name:     "merge with no conflicts",
			existing: map[string]string{"key1": "value1"},
			new:      map[string]string{"key2": "value2"},
			expected: map[string]string{"key1": "value1", "key2": "value2"},
		},
		{
			name:     "merge with conflicts",
			existing: map[string]string{"key1": "value1"},
			new:      map[string]string{"key1": "newValue1", "key2": "value2"},
			expected: map[string]string{"key1": "newValue1", "key2": "value2"},
		},
		{
			name:     "merge with empty new map",
			existing: map[string]string{"key1": "value1"},
			new:      map[string]string{},
			expected: map[string]string{"key1": "value1"},
		},
		{
			name:     "merge with empty existing map",
			existing: map[string]string{},
			new:      map[string]string{"key1": "value1"},
			expected: map[string]string{"key1": "value1"},
		},
		{
			name:     "merge with both maps empty",
			existing: map[string]string{},
			new:      map[string]string{},
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mergeMaps(tt.existing, tt.new)
			assert.Equal(t, tt.expected, tt.existing)
		})
	}
}
