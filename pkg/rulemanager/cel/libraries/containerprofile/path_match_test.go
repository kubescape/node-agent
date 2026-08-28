package containerprofile

import (
	"testing"

	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
	"github.com/stretchr/testify/assert"
)

func TestMatchLiteralPath_DifferentialAgainstCompareDynamic(t *testing.T) {
	// Corpus of literal values and queries testing all slash, empty, root, and subpath combinations
	candidates := []string{
		"",
		"/",
		"//",
		"///",
		"/a",
		"/a/",
		"/a//",
		"/a/b",
		"/a/b/",
		"/a/b//",
		"/etc/passwd",
		"/etc/passwd/",
		"/etc/passwd//",
		"/var/log/app.log",
		"/var/log/app.log/",
		"relative/path",
		"relative/path/",
	}

	for _, val := range candidates {
		valuesMap := map[string]struct{}{val: {}}

		for _, query := range candidates {
			expected := dynamicpathdetector.CompareDynamic(val, query)
			actual := matchLiteralPath(valuesMap, query)

			assert.Equalf(t, expected, actual,
				"disagreement between CompareDynamic and matchLiteralPath for value=%q query=%q", val, query)
		}
	}
}

func TestMatchLiteralPath_MultiEntryValues(t *testing.T) {
	values := map[string]struct{}{
		"/bin/bash":   {},
		"/etc/nginx/": {},
		"/":           {},
	}

	assert.True(t, matchLiteralPath(values, "/bin/bash"))
	assert.True(t, matchLiteralPath(values, "/bin/bash/"))
	assert.True(t, matchLiteralPath(values, "/etc/nginx"))
	assert.True(t, matchLiteralPath(values, "/etc/nginx/"))
	assert.True(t, matchLiteralPath(values, "/"))
	assert.False(t, matchLiteralPath(values, "//"))
	assert.False(t, matchLiteralPath(values, ""))
	assert.False(t, matchLiteralPath(values, "/bin/sh"))
}
