package iouring

import iouringsyscall "github.com/iceber/iouring-go/syscall"

// OpcodeMap maps opcodes to their string descriptions
var OpcodeMap = map[uint8]string{
	iouringsyscall.IORING_OP_NOP:             "No operation",
	iouringsyscall.IORING_OP_READV:           "Vector read",
	iouringsyscall.IORING_OP_WRITEV:          "Vector write",
	iouringsyscall.IORING_OP_FSYNC:           "File sync",
	iouringsyscall.IORING_OP_READ_FIXED:      "Read with fixed buffers",
	iouringsyscall.IORING_OP_WRITE_FIXED:     "Write with fixed buffers",
	iouringsyscall.IORING_OP_POLL_ADD:        "Add poll request",
	iouringsyscall.IORING_OP_POLL_REMOVE:     "Remove poll request",
	iouringsyscall.IORING_OP_SYNC_FILE_RANGE: "Sync file range",
	iouringsyscall.IORING_OP_SENDMSG:         "Send message",
	iouringsyscall.IORING_OP_RECVMSG:         "Receive message",
	iouringsyscall.IORING_OP_TIMEOUT:         "Timeout operation",
	iouringsyscall.IORING_OP_TIMEOUT_REMOVE:  "Remove timeout",
	iouringsyscall.IORING_OP_ACCEPT:          "Accept connection",
	iouringsyscall.IORING_OP_ASYNC_CANCEL:    "Cancel async operation",
	iouringsyscall.IORING_OP_LINK_TIMEOUT:    "Link timeout",
	iouringsyscall.IORING_OP_CONNECT:         "Connect socket",
	iouringsyscall.IORING_OP_FALLOCATE:       "Preallocate file space",
	iouringsyscall.IORING_OP_OPENAT:          "Open file (relative)",
	iouringsyscall.IORING_OP_CLOSE:           "Close file",
	iouringsyscall.IORING_OP_FILES_UPDATE:    "Update registered files",
	iouringsyscall.IORING_OP_STATX:           "Get file status",
	iouringsyscall.IORING_OP_READ:            "Read",
	iouringsyscall.IORING_OP_WRITE:           "Write",
	iouringsyscall.IORING_OP_FADVISE:         "File access pattern advice",
	iouringsyscall.IORING_OP_MADVISE:         "Memory access pattern advice",
	iouringsyscall.IORING_OP_SEND:            "Send data",
	iouringsyscall.IORING_OP_RECV:            "Receive data",
	iouringsyscall.IORING_OP_OPENAT2:         "Enhanced open file (relative)",
	iouringsyscall.IORING_OP_EPOLL_CTL:       "Epoll control",
	iouringsyscall.IORING_OP_SPLICE:          "Splice data",
	iouringsyscall.IORING_OP_PROVIDE_BUFFERS: "Provide buffers",
	iouringsyscall.IORING_OP_REMOVE_BUFFERS:  "Remove buffers",
	iouringsyscall.IORING_OP_TEE:             "Tee data",
	iouringsyscall.IORING_OP_SHUTDOWN:        "Shutdown connection",
	iouringsyscall.IORING_OP_RENAMEAT:        "Rename file (relative)",
	iouringsyscall.IORING_OP_UNLINKAT:        "Unlink file (relative)",
	iouringsyscall.IORING_OP_MKDIRAT:         "Make directory (relative)",
	iouringsyscall.IORING_OP_SYMLINKAT:       "Create symbolic link (relative)",
	iouringsyscall.IORING_OP_LINKAT:          "Create hard link (relative)",
	iouringsyscall.IORING_OP_MSG_RING:        "Message ring",
	iouringsyscall.IORING_OP_FSETXATTR:       "Set file extended attribute",
	iouringsyscall.IORING_OP_SETXATTR:        "Set extended attribute",
	iouringsyscall.IORING_OP_FGETXATTR:       "Get file extended attribute",
	iouringsyscall.IORING_OP_GETXATTR:        "Get extended attribute",
	iouringsyscall.IORING_OP_SOCKET:          "Create socket",
	iouringsyscall.IORING_OP_URING_CMD:       "io_uring command",
	iouringsyscall.IORING_OP_SEND_ZC:         "Zero-copy send",
}

// GetOpcodeName returns the string description of an opcode
func GetOpcodeName(opcode uint8) (bool, string) {
	if name, ok := OpcodeMap[opcode]; ok {
		return true, name
	}
	return false, "Unknown operation"
}

// GetSuspiciousOpcodes returns a list of opcodes that might be considered suspicious
// These are operations that could potentially be used maliciously
func GetSuspiciousOpcodes() []uint8 {
	return []uint8{
		iouringsyscall.IORING_OP_OPENAT, // File operations that could be suspicious
		iouringsyscall.IORING_OP_OPENAT2,
		iouringsyscall.IORING_OP_UNLINKAT,
		iouringsyscall.IORING_OP_RENAMEAT,
		iouringsyscall.IORING_OP_SYMLINKAT,
		iouringsyscall.IORING_OP_LINKAT,
		iouringsyscall.IORING_OP_SOCKET, // Network operations that could be suspicious
		iouringsyscall.IORING_OP_CONNECT,
		iouringsyscall.IORING_OP_SEND_ZC,
		iouringsyscall.IORING_OP_SETXATTR, // Extended attribute operations
		iouringsyscall.IORING_OP_FSETXATTR,
		iouringsyscall.IORING_OP_URING_CMD, // Direct device access
	}
}
