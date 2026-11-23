package igbackend

import (
	"fmt"
	"strings"

	privpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/policy"
)

// Names of the gadgets' enums, in enum order, as verdict events name them
// (lower case, prefix removed). A summary record names its hook and detail
// from these tables: the hook of a hidden attempt often had no verdict event
// to learn it from. TestSummaryNamesMatchEnums checks them against the
// program sources.
var (
	privHookNames = []string{"userns_create", "task_alloc", "capable", "sb_mount", "sb_kern_mount", "sb_umount", "move_mount",
		"sb_pivotroot", "path_chroot", "anon_inode", "ptrace_access_check", "ptrace_traceme", "kernel_read_file",
		"kernel_load_data", "kernel_module_request", "bpf", "perf_event_open", "key_alloc", "key_permission", "inode_mknod",
		"task_fix_setuid", "task_fix_setgid", "capset", "fault"}
	privSyscallNames = []string{"none", "unshare", "setns", "clone", "clone3", "mount", "umount2", "pivot_root", "chroot",
		"open_tree", "move_mount", "fsopen", "fsmount", "fspick", "mount_setattr", "ptrace", "process_vm_readv",
		"process_vm_writev", "init_module", "finit_module", "bpf", "perf_event_open", "kexec_load", "keyctl", "userfaultfd",
		"io_uring_setup", "mknod", "setuid", "setgid", "capset"}
	fileHookNames = []string{"file_open", "path_truncate", "path_mknod", "path_mkdir", "path_symlink", "path_link",
		"path_unlink", "path_rmdir", "path_rename", "path_chmod", "path_chown", "inode_setxattr", "inode_set_acl",
		"root_barrier", "fault", "inode_setattr", "inode_removexattr", "inode_remove_acl"}
	fileAccessNames = []string{"read", "write", "create", "delete", "rename", "chmod", "move_source", "new_name"}
	netHookNames    = []string{"socket_connect", "socket_sendmsg", "fault"}
	capabilityNames = func() map[uint32]string {
		names := make(map[uint32]string, len(privpolicy.Capabilities))
		for name, n := range privpolicy.Capabilities {
			names[n] = name
		}
		return names
	}()
)

// summaryNames names a summary's hook and detail (see common/verdict.h):
// privilege: the capability (CAP_*, bits 0-7, 255 for none) and the syscall
// (from bit 8); file: the access kind; network: none. An unknown number
// keeps it.
func summaryNames(section string, hook, detail uint32) (string, string) {
	pick := func(names []string, n uint32, what string) string {
		if int(n) < len(names) {
			return names[n]
		}
		return fmt.Sprintf("%s %d", what, n)
	}
	switch section {
	case "privilege":
		var parts []string
		if c := detail & 0xff; c != 0xff {
			if name, ok := capabilityNames[c]; ok {
				parts = append(parts, "CAP_"+name)
			} else {
				parts = append(parts, fmt.Sprintf("capability %d", c))
			}
		}
		if sc := detail >> 8; sc != 0 {
			parts = append(parts, "syscall "+pick(privSyscallNames, sc, "syscall"))
		}
		return pick(privHookNames, hook, "hook"), strings.Join(parts, " ")
	case "file":
		return pick(fileHookNames, hook, "hook"), pick(fileAccessNames, detail, "access")
	case "network":
		return pick(netHookNames, hook, "hook"), ""
	}
	return fmt.Sprintf("hook %d", hook), ""
}
