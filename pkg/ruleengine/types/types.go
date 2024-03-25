package types

import (
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type SyscallEvent struct {
	eventtypes.BasicK8sMetadata

	// Syscall event specific fields
	SyscallName string
}
