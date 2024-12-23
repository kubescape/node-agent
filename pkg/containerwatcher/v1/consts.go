package containerwatcher

// The numbers can be arbitrary identifiers since they're not actually used for system calls,
// so we don't need to handle other architecture specifically.
const (
	SYS_LINKAT    = 265
	SYS_LINK      = 86
	SYS_SYMLINKAT = 266
	SYS_SYMLINK   = 88
	SYS_OPEN      = 2
	SYS_OPENAT    = 257
	SYS_EXECVE    = 59
	SYS_FORK      = 57
)
