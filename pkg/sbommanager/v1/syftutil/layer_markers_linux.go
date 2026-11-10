//go:build linux

package syftutil

import "golang.org/x/sys/unix"

// opaqueXattrs are the attributes containerd sets on an opaque directory:
// trusted.overlay.opaque, or user.overlay.opaque when the snapshotter mounts
// with userxattr. Reading the trusted namespace needs CAP_SYS_ADMIN, which
// node-agent has.
var opaqueXattrs = []string{"trusted.overlay.opaque", "user.overlay.opaque"}

// isWhiteoutDevice reports whether p is an overlayfs whiteout: a character
// device with device number 0/0.
func isWhiteoutDevice(p string) bool {
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil {
		return false
	}
	return st.Mode&unix.S_IFMT == unix.S_IFCHR && st.Rdev == 0
}

// isOpaqueDir reports whether directory p is marked opaque (xattr value "y").
func isOpaqueDir(p string) bool {
	buf := make([]byte, 1)
	for _, name := range opaqueXattrs {
		n, err := unix.Lgetxattr(p, name, buf)
		if err == nil && n == 1 && buf[0] == 'y' {
			return true
		}
	}
	return false
}
