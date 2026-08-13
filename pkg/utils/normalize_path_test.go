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
			name:     "absolute proc path",
			input:    "/proc/46/fd/3",
			expected: "/proc/46/fd/3",
		},
		{
			// The gadget resolves relative opens against their dirfd/cwd, so a
			// numeric first segment is a genuine directory name and must be
			// left untouched, not re-rooted under /proc.
			name:     "numeric first segment stays literal",
			input:    "/46/task/46/fd",
			expected: "/46/task/46/fd",
		},
		{
			// Same case arriving relative (no leading slash): it must only gain
			// a leading slash, not be re-rooted under /proc.
			name:     "relative numeric first segment is not re-rooted",
			input:    "46/task/46/fd",
			expected: "/46/task/46/fd",
		},
		{
			name:     "non-proc path with data dir",
			input:    "/data/appendonlydir/x",
			expected: "/data/appendonlydir/x",
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
