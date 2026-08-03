package utils

import (
	"path"
	"regexp"
	"strings"
)

// headlessProcRegex matches a headless /proc/<pid>/<file> path — a /proc/<pid>/...
// path stripped of its /proc root — which NormalizePath re-roots under /proc.
//
// The allowlist enumerates the /proc/<pid> entries opened by runc:[2:INIT]
// during container/user-namespace setup. It was previously only (task|fd),
// which let the sibling entries (setgroups, gid_map, uid_map, status, cgroup,
// ...) leak /proc-less into learned ContainerProfiles — a regression of #721.
// It stays an explicit allowlist rather than a bare `^/\d+` catch-all so a
// genuine top-level numeric directory is never misread as a PID; extend it if
// another /proc/<pid> entry is observed leaking.
var headlessProcRegex = regexp.MustCompile(`^/\d+/(task|fd|setgroups|gid_map|uid_map|status|stat|cgroup|mountinfo|maps|environ|comm|cmdline|ns)(/|$)`)

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
