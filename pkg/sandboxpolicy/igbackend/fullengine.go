package igbackend

import (
	"context"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	execruntime "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/runtime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

// FullStartConfig supplies trusted runtime evidence, never policy annotations.
// Acquire transfers ownership of its lease (including partial error results) to
// the instance. ImageOrigins must remain pinned by that lease until Stop succeeds.
type FullStartConfig struct {
	Binding      sandboxpolicy.Binding
	Program      *fullpolicy.KernelProgram
	Acquire      func(context.Context) (fullruntime.BindingLease, error)
	ImageOrigins *execruntime.ImageOriginSnapshot
}

// FullEngine prepares one persistent owner without activating its first policy.
// Install event provenance BEFORE Start and Activate. A non-nil instance returned
// with an error still owns resources: retain it and retry Stop until successful.
// Start may run concurrently for distinct bindings. Instance operations are
// serialized per binding; Close runs only after all Start/instance work joins.
// Event callbacks must not reenter lifecycle methods or block on their locks.
type FullEngine interface {
	Start(context.Context, string, FullStartConfig, func(RawFullVerdict)) (FullInstance, error)
}

// FullEngineCloser optionally owns node-wide resources shared by instances.
// The backend calls Close only after every instance and untransferred lease has
// drained. An error retains ownership for retry; success is called only once.
// Close must not release the borrowed runtime or binding source: their caller
// closes those only after backend Close succeeds. Legacy engines need no Close.
type FullEngineCloser interface {
	Close(context.Context) error
}

// FullInstance reloads the same kernel owner; it never replaces the gadget.
// A publication error may have Committed=true. Resume the same pending generation
// rather than creating another owner or rolling back successful role epochs.
type FullInstance interface {
	Activate(context.Context) (fullruntime.PublicationResult, error)
	Update(context.Context, *fullpolicy.KernelProgram) (fullruntime.PublicationResult, error)
	Resume(context.Context) (fullruntime.PublicationResult, error)
	Generation() uint64
	PendingGeneration() uint64
	Epochs() map[string]uint64
	Check(context.Context) error
	// Detached confirms manager teardown, even if releasing pins still fails.
	Detached() bool
	Stop(context.Context) error
}

// FullKernelCounterSource is optional telemetry, independent of readiness.
// Successful Stop must retain a Final snapshot or an explicit unavailable error.
type FullKernelCounterSource interface {
	KernelEventCounters() (fullruntime.KernelEventCounters, error)
}

// KernelEventTotals contains successfully read kernel counter contributions.
// On read failure, the last successful sample is retained as a lower bound.
// These counters exclude early native owner refusals; Lost measures failed ring
// reservations, not userspace queue loss or complete denied-exec event coverage.
type KernelEventTotals struct {
	Submitted, Lost, ObservationErrors uint64
}

// KernelEventStats covers this backend's lifetime (not process restarts).
// Owned includes partial-startup and retiring instances. Retired retains final
// snapshots after instance removal. Unavailable counts MUST be checked before
// interpreting zero loss. Live snapshots are not atomic across CPUs/instances.
type KernelEventStats struct {
	Owned, Retired                       KernelEventTotals
	OwnedInstances, OwnedUnavailable     uint64
	RetiredInstances, RetiredUnavailable uint64
}

// FullPendingAborter optionally discards an uncommitted candidate without
// changing the last committed policy. A committed candidate must not abort.
type FullPendingAborter interface {
	AbortPending(context.Context) error
}
