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

// IsResolvedFullPath reports whether p is usable as a gadget-resolved full
// path (the "fpath" field of an open event).
//
// The gadget builds that field by walking the dentry chain backwards into a
// per-CPU scratch buffer which is never cleared between events. When the walk
// contributes nothing, the buffer's previous contents are returned instead,
// so the field can carry a fragment of an unrelated event's path — including
// one belonging to a different container on the same node.
//
// A successful walk always emits a leading slash before returning, so a
// non-empty value that is not absolute cannot have come from one. That makes
// the leading slash a reliable boundary check for the fragment case.
//
// Callers must NOT apply this to "fname": that field is the raw syscall
// argument and is legitimately relative when openat is used with a dirfd.
//
// This does not catch every stale value. When the returned pointer happens to
// land on the start of a previous complete path the result is absolute and
// indistinguishable by shape; that case can only be fixed in the gadget, by
// returning NULL for an empty walk and by clearing the scratch buffer.
func IsResolvedFullPath(p string) bool {
	return p != "" && strings.HasPrefix(p, "/")
}

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
