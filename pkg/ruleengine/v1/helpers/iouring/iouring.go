package iouring

const (
	IORING_OP_NOP uint32 = iota
	IORING_OP_READV
	IORING_OP_WRITEV
	IORING_OP_FSYNC
	IORING_OP_READ_FIXED
	IORING_OP_WRITE_FIXED
	IORING_OP_POLL_ADD
	IORING_OP_POLL_REMOVE
	IORING_OP_SYNC_FILE_RANGE
	IORING_OP_SENDMSG
	IORING_OP_RECVMSG
	IORING_OP_TIMEOUT
	IORING_OP_TIMEOUT_REMOVE
	IORING_OP_ACCEPT
	IORING_OP_ASYNC_CANCEL
	IORING_OP_LINK_TIMEOUT
	IORING_OP_CONNECT
	IORING_OP_FALLOCATE
	IORING_OP_OPENAT
	IORING_OP_CLOSE
	IORING_OP_FILES_UPDATE
	IORING_OP_STATX
	IORING_OP_READ
	IORING_OP_WRITE
	IORING_OP_FADVISE
	IORING_OP_MADVISE
	IORING_OP_SEND
	IORING_OP_RECV
	IORING_OP_OPENAT2
	IORING_OP_EPOLL_CTL
	IORING_OP_SPLICE
	IORING_OP_PROVIDE_BUFFERS
	IORING_OP_REMOVE_BUFFERS
	IORING_OP_TEE
	IORING_OP_SHUTDOWN
	IORING_OP_RENAMEAT
	IORING_OP_UNLINKAT
	IORING_OP_MKDIRAT
	IORING_OP_SYMLINKAT
	IORING_OP_LINKAT
	// Added in 5.11
	IORING_OP_MSG_RING
	// Added in 5.12
	IORING_OP_FSETXATTR
	IORING_OP_SETXATTR
	IORING_OP_FGETXATTR
	IORING_OP_GETXATTR
	IORING_OP_SOCKET
	// Added in 5.13
	IORING_OP_URING_CMD
	// Added in 5.14
	IORING_OP_SEND_ZC
	IORING_OP_SEND_ZC_FIXED
)

// OpcodeMap maps opcodes to their string descriptions
var OpcodeMap = map[uint32]string{
	IORING_OP_NOP:             "No operation",
	IORING_OP_READV:           "Vector read",
	IORING_OP_WRITEV:          "Vector write",
	IORING_OP_FSYNC:           "File sync",
	IORING_OP_READ_FIXED:      "Read with fixed buffers",
	IORING_OP_WRITE_FIXED:     "Write with fixed buffers",
	IORING_OP_POLL_ADD:        "Add poll request",
	IORING_OP_POLL_REMOVE:     "Remove poll request",
	IORING_OP_SYNC_FILE_RANGE: "Sync file range",
	IORING_OP_SENDMSG:         "Send message",
	IORING_OP_RECVMSG:         "Receive message",
	IORING_OP_TIMEOUT:         "Timeout operation",
	IORING_OP_TIMEOUT_REMOVE:  "Remove timeout",
	IORING_OP_ACCEPT:          "Accept connection",
	IORING_OP_ASYNC_CANCEL:    "Cancel async operation",
	IORING_OP_LINK_TIMEOUT:    "Link timeout",
	IORING_OP_CONNECT:         "Connect socket",
	IORING_OP_FALLOCATE:       "Preallocate file space",
	IORING_OP_OPENAT:          "Open file (relative)",
	IORING_OP_CLOSE:           "Close file",
	IORING_OP_FILES_UPDATE:    "Update registered files",
	IORING_OP_STATX:           "Get file status",
	IORING_OP_READ:            "Read",
	IORING_OP_WRITE:           "Write",
	IORING_OP_FADVISE:         "File access pattern advice",
	IORING_OP_MADVISE:         "Memory access pattern advice",
	IORING_OP_SEND:            "Send data",
	IORING_OP_RECV:            "Receive data",
	IORING_OP_OPENAT2:         "Enhanced open file (relative)",
	IORING_OP_EPOLL_CTL:       "Epoll control",
	IORING_OP_SPLICE:          "Splice data",
	IORING_OP_PROVIDE_BUFFERS: "Provide buffers",
	IORING_OP_REMOVE_BUFFERS:  "Remove buffers",
	IORING_OP_TEE:             "Tee data",
	IORING_OP_SHUTDOWN:        "Shutdown connection",
	IORING_OP_RENAMEAT:        "Rename file (relative)",
	IORING_OP_UNLINKAT:        "Unlink file (relative)",
	IORING_OP_MKDIRAT:         "Make directory (relative)",
	IORING_OP_SYMLINKAT:       "Create symbolic link (relative)",
	IORING_OP_LINKAT:          "Create hard link (relative)",
	IORING_OP_MSG_RING:        "Message ring",
	IORING_OP_FSETXATTR:       "Set file extended attribute",
	IORING_OP_SETXATTR:        "Set extended attribute",
	IORING_OP_FGETXATTR:       "Get file extended attribute",
	IORING_OP_GETXATTR:        "Get extended attribute",
	IORING_OP_SOCKET:          "Create socket",
	IORING_OP_URING_CMD:       "io_uring command",
	IORING_OP_SEND_ZC:         "Zero-copy send",
	IORING_OP_SEND_ZC_FIXED:   "Zero-copy send with fixed buffers",
}

// GetOpcodeName returns the string description of an opcode
func GetOpcodeName(opcode uint32) (bool, string) {
	if name, ok := OpcodeMap[opcode]; ok {
		return true, name
	}
	return false, "Unknown operation"
}

// GetSuspiciousOpcodes returns a list of opcodes that might be considered suspicious
// These are operations that could potentially be used maliciously
func GetSuspiciousOpcodes() []uint32 {
	return []uint32{
		IORING_OP_OPENAT, // File operations that could be suspicious
		IORING_OP_OPENAT2,
		IORING_OP_UNLINKAT,
		IORING_OP_RENAMEAT,
		IORING_OP_SYMLINKAT,
		IORING_OP_LINKAT,
		IORING_OP_SOCKET, // Network operations that could be suspicious
		IORING_OP_CONNECT,
		IORING_OP_SEND_ZC,
		IORING_OP_SEND_ZC_FIXED,
		IORING_OP_SETXATTR, // Extended attribute operations
		IORING_OP_FSETXATTR,
		IORING_OP_URING_CMD, // Direct device access
	}
}
