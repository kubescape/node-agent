package utils

import (
	"os"
	"path"
	"strconv"
	"strings"
)

// AT_FDCWD is the Linux sentinel indicating paths are relative to the current working directory.
const AT_FDCWD int32 = -100

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

// ResolveOpenPathProc resolves a non-absolute open path via procfs (the agent
// runs hostPID). When fdValid is true (error_raw == 0), the returned fd names
// the opened object exactly — covering ".", relative names, descriptor 0 and
// AT_EMPTY_PATH re-opens. When fdValid is false, a relative open resolves against
// its base directory: if dirfd is AT_FDCWD (or omitted), it joins with /proc/<pid>/cwd;
// if dirfd is a valid directory descriptor, it joins with /proc/<pid>/fd/<dirfd>; an invalid
// or non-directory dirfd fails resolution to avoid attributing to cwd or fabricating
// a path. An empty raw with no usable fd is unresolvable by kernel semantics:
// openat("") names no filesystem object.
func ResolveOpenPathProc(pid, fd uint32, fdValid bool, raw string, dirfd ...int32) string {
	if pid == 0 {
		return ""
	}
	if fdValid {
		if target, err := os.Readlink("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/fd/" + strconv.FormatUint(uint64(fd), 10)); err == nil && strings.HasPrefix(target, "/") {
			return target
		}
	}
	if raw == "" {
		return ""
	}
	dfd := AT_FDCWD
	if len(dirfd) > 0 {
		dfd = dirfd[0]
	}
	pidStr := strconv.FormatUint(uint64(pid), 10)
	if dfd == AT_FDCWD {
		if cwd, err := os.Readlink("/proc/" + pidStr + "/cwd"); err == nil && strings.HasPrefix(cwd, "/") {
			return path.Join(cwd, raw)
		}
		return ""
	}
	if dfd >= 0 {
		fdPath := "/proc/" + pidStr + "/fd/" + strconv.FormatInt(int64(dfd), 10)
		if fi, err := os.Stat(fdPath); err == nil && fi.IsDir() {
			if base, err := os.Readlink(fdPath); err == nil && strings.HasPrefix(base, "/") {
				return path.Join(base, raw)
			}
		}
	}
	return ""
}

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
