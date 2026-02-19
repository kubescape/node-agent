package utils

import (
	"path"
	"regexp"
	"strings"
)

var headlessProcRegex = regexp.MustCompile(`^/\d+/(task|fd)/`)

// NormalizePath normalizes a path by:
// 1. Prepending "/proc" to "headless" proc paths (e.g. /46/task/46/fd -> /proc/46/task/46/fd)
// 2. Ensuring it starts with "/" if it's not empty
// 3. Converting "." to "/"
// 4. Cleaning the path (removing redundant slashes, dot-dots, etc.)
func NormalizePath(p string) string {
	if p == "" {
		return ""
	}

	if p == "." {
		return "/"
	}

	if headlessProcRegex.MatchString(p) {
		p = "/proc" + p
	}

	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}

	return path.Clean(p)
}
