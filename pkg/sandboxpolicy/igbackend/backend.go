// Package igbackend owns strict execution-policy gadgets: the full backend on
// IG's shared CO-RE exec engine, and the privilege, network and file
// sections. Unsupported semantics are errors, never silently weakened rules.
package igbackend

import (
	"context"

	execruntime "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/runtime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

// Lease pins the exact live identity for the entire instance lifetime.
type Lease interface {
	Check() error
	Close() error
}
type Validator interface {
	Acquire(context.Context, sandboxpolicy.Binding) (Lease, error)
}

type identity struct {
	runtime, container, path string
	cgroup, mountns          uint64
	pid                      uint32
}

func key(b sandboxpolicy.Binding) identity {
	return identity{b.Runtime, b.ContainerID, b.CgroupPath, b.CgroupID, b.MountNamespace, b.PID}
}
func native(b sandboxpolicy.Binding) execruntime.ContainerIdentity {
	return execruntime.ContainerIdentity{Runtime: b.Runtime, ID: b.ContainerID, CgroupID: b.CgroupID, CgroupPath: b.CgroupPath}
}
