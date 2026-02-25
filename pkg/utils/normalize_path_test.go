package utils

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty path",
			input:    "",
			expected: "",
		},
		{
			name:     "dot path",
			input:    ".",
			expected: "/",
		},
		{
			name:     "absolute path",
			input:    "/etc/passwd",
			expected: "/etc/passwd",
		},
		{
			name:     "headless proc path (task)",
			input:    "/46/task/46/fd",
			expected: "/proc/46/task/46/fd",
		},
		{
			name:     "headless proc path (fd)",
			input:    "/46/fd/3",
			expected: "/proc/46/fd/3",
		},
		{
			name:     "already absolute proc path",
			input:    "/proc/46/fd/3",
			expected: "/proc/46/fd/3",
		},
		{
			name:     "relative path (not dot)",
			input:    "usr/bin/ls",
			expected: "/usr/bin/ls",
		},
		{
			name:     "relative path with ./",
			input:    "./config",
			expected: "/config",
		},
		{
			name:     "path with redundant slashes",
			input:    "/etc//passwd",
			expected: "/etc/passwd",
		},
		{
			name:     "path with dot components",
			input:    "/usr/./bin/../lib",
			expected: "/usr/lib",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizePath(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}
