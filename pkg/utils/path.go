package utils

import (
	"path"
	"regexp"
	"strings"
)

// headlessProcRegex matches any path whose leading segment is a bare PID — the
// residue of a /proc/<pid>/... path stripped of its /proc root. A top-level
// numeric segment is never a real filesystem path node-agent should record, so
// the entire class is normalized back under /proc.
//
// The allowlist was previously narrowed to `(task|fd)`, which let sibling
// headless paths written by runc:[2:INIT] during user-namespace setup —
// /<pid>/setgroups, /<pid>/gid_map, /<pid>/uid_map, /<pid>/status, /<pid>/cgroup,
// ... — leak /proc-less into learned ContainerProfiles (a regression of #721).
var headlessProcRegex = regexp.MustCompile(`^/\d+(/|$)`)

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
