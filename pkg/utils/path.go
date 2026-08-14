package utils

import (
	"path"
	"strings"
)

// NormalizePath normalizes a path by:
// 1. Ensuring it starts with "/" if it's not empty
// 2. Converting "." to "/"
// 3. Cleaning the path (removing redundant slashes, dot-dots, etc.)
func NormalizePath(p string) string {
	if p == "" {
		return ""
	}

	if p == "." {
		return "/"
	}

	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}

	return path.Clean(p)
}
