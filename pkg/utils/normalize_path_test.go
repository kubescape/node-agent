package utils

import (
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
			name:     "terminal headless proc fd path",
			input:    "/46/fd",
			expected: "/proc/46/fd",
		},
		{
			name:     "terminal headless proc task path",
			input:    "/46/task",
			expected: "/proc/46/task",
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
			if got := NormalizePath(tt.input); got != tt.expected {
				t.Errorf("NormalizePath(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
